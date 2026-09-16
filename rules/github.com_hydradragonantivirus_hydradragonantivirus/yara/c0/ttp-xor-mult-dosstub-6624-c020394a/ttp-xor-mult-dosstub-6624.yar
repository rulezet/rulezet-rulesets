rule TTP_XOR_MULT_DOSStub_6624 {
  strings:
    $key_6624 = { 32 4c [2] 46 54 [2] 01 56 [2] 46 47 [2] 08 4b [2] 04 41 [2] 13 4a [2] 08 04 [2] 35 }

  condition:
    any of them
}