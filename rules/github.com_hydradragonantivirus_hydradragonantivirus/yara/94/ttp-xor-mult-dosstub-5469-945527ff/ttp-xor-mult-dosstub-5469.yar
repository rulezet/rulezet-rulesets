rule TTP_XOR_MULT_DOSStub_5469 {
  strings:
    $key_5469 = { 00 01 [2] 74 19 [2] 33 1b [2] 74 0a [2] 3a 06 [2] 36 0c [2] 21 07 [2] 3a 49 [2] 07 }

  condition:
    any of them
}