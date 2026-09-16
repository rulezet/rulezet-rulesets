rule TTP_XOR_MULT_DOSStub_6669 {
  strings:
    $key_6669 = { 32 01 [2] 46 19 [2] 01 1b [2] 46 0a [2] 08 06 [2] 04 0c [2] 13 07 [2] 08 49 [2] 35 }

  condition:
    any of them
}