rule TTP_XOR_MULT_DOSStub_1069 {
  strings:
    $key_1069 = { 44 01 [2] 30 19 [2] 77 1b [2] 30 0a [2] 7e 06 [2] 72 0c [2] 65 07 [2] 7e 49 [2] 43 }

  condition:
    any of them
}