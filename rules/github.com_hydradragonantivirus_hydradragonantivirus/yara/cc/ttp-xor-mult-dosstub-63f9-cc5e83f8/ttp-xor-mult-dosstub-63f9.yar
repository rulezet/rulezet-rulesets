rule TTP_XOR_MULT_DOSStub_63f9 {
  strings:
    $key_63f9 = { 37 91 [2] 43 89 [2] 04 8b [2] 43 9a [2] 0d 96 [2] 01 9c [2] 16 97 [2] 0d d9 [2] 30 }

  condition:
    any of them
}