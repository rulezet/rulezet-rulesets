rule TTP_XOR_MULT_DOSStub_6648 {
  strings:
    $key_6648 = { 32 20 [2] 46 38 [2] 01 3a [2] 46 2b [2] 08 27 [2] 04 2d [2] 13 26 [2] 08 68 [2] 35 }

  condition:
    any of them
}