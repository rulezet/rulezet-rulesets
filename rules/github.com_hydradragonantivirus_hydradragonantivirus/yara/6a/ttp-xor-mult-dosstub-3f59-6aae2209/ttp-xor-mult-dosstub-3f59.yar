rule TTP_XOR_MULT_DOSStub_3f59 {
  strings:
    $key_3f59 = { 6b 31 [2] 1f 29 [2] 58 2b [2] 1f 3a [2] 51 36 [2] 5d 3c [2] 4a 37 [2] 51 79 [2] 6c }

  condition:
    any of them
}