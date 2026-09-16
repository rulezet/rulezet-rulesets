rule TTP_XOR_MULT_DOSStub_6602 {
  strings:
    $key_6602 = { 32 6a [2] 46 72 [2] 01 70 [2] 46 61 [2] 08 6d [2] 04 67 [2] 13 6c [2] 08 22 [2] 35 }

  condition:
    any of them
}