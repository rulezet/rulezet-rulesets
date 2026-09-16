rule TTP_XOR_MULT_DOSStub_6605 {
  strings:
    $key_6605 = { 32 6d [2] 46 75 [2] 01 77 [2] 46 66 [2] 08 6a [2] 04 60 [2] 13 6b [2] 08 25 [2] 35 }

  condition:
    any of them
}