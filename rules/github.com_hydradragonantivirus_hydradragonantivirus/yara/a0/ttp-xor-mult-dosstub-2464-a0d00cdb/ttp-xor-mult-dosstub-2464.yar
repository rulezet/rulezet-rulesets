rule TTP_XOR_MULT_DOSStub_2464 {
  strings:
    $key_2464 = { 70 0c [2] 04 14 [2] 43 16 [2] 04 07 [2] 4a 0b [2] 46 01 [2] 51 0a [2] 4a 44 [2] 77 }

  condition:
    any of them
}