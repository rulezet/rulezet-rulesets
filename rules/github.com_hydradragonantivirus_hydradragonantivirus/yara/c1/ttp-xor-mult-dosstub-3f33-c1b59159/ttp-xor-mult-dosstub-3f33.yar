rule TTP_XOR_MULT_DOSStub_3f33 {
  strings:
    $key_3f33 = { 6b 5b [2] 1f 43 [2] 58 41 [2] 1f 50 [2] 51 5c [2] 5d 56 [2] 4a 5d [2] 51 13 [2] 6c }

  condition:
    any of them
}