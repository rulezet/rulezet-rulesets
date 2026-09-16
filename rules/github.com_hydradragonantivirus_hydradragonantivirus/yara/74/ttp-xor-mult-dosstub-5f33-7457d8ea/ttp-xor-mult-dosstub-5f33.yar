rule TTP_XOR_MULT_DOSStub_5f33 {
  strings:
    $key_5f33 = { 0b 5b [2] 7f 43 [2] 38 41 [2] 7f 50 [2] 31 5c [2] 3d 56 [2] 2a 5d [2] 31 13 [2] 0c }

  condition:
    any of them
}