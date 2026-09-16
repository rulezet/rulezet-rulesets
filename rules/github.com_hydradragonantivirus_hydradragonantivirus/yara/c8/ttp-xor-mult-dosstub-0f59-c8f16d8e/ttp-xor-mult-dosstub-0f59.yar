rule TTP_XOR_MULT_DOSStub_0f59 {
  strings:
    $key_0f59 = { 5b 31 [2] 2f 29 [2] 68 2b [2] 2f 3a [2] 61 36 [2] 6d 3c [2] 7a 37 [2] 61 79 [2] 5c }

  condition:
    any of them
}