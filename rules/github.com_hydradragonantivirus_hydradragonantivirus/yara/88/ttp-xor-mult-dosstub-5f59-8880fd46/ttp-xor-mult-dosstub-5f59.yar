rule TTP_XOR_MULT_DOSStub_5f59 {
  strings:
    $key_5f59 = { 0b 31 [2] 7f 29 [2] 38 2b [2] 7f 3a [2] 31 36 [2] 3d 3c [2] 2a 37 [2] 31 79 [2] 0c }

  condition:
    any of them
}