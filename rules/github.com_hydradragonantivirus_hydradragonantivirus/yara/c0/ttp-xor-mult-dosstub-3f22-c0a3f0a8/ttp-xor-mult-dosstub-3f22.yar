rule TTP_XOR_MULT_DOSStub_3f22 {
  strings:
    $key_3f22 = { 6b 4a [2] 1f 52 [2] 58 50 [2] 1f 41 [2] 51 4d [2] 5d 47 [2] 4a 4c [2] 51 02 [2] 6c }

  condition:
    any of them
}