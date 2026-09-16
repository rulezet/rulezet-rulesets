rule TTP_XOR_MULT_DOSStub_6662 {
  strings:
    $key_6662 = { 32 0a [2] 46 12 [2] 01 10 [2] 46 01 [2] 08 0d [2] 04 07 [2] 13 0c [2] 08 42 [2] 35 }

  condition:
    any of them
}