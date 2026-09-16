rule TTP_XOR_MULT_DOSStub_2469 {
  strings:
    $key_2469 = { 70 01 [2] 04 19 [2] 43 1b [2] 04 0a [2] 4a 06 [2] 46 0c [2] 51 07 [2] 4a 49 [2] 77 }

  condition:
    any of them
}