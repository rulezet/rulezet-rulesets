rule TTP_XOR_MULT_DOSStub_6628 {
  strings:
    $key_6628 = { 32 40 [2] 46 58 [2] 01 5a [2] 46 4b [2] 08 47 [2] 04 4d [2] 13 46 [2] 08 08 [2] 35 }

  condition:
    any of them
}