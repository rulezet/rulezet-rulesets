rule TTP_XOR_MULT_DOSStub_2868 {
  strings:
    $key_2868 = { 7c 00 [2] 08 18 [2] 4f 1a [2] 08 0b [2] 46 07 [2] 4a 0d [2] 5d 06 [2] 46 48 [2] 7b }

  condition:
    any of them
}