rule TTP_XOR_MULT_DOSStub_2872 {
  strings:
    $key_2872 = { 7c 1a [2] 08 02 [2] 4f 00 [2] 08 11 [2] 46 1d [2] 4a 17 [2] 5d 1c [2] 46 52 [2] 7b }

  condition:
    any of them
}