rule TTP_XOR_MULT_DOSStub_3868 {
  strings:
    $key_3868 = { 6c 00 [2] 18 18 [2] 5f 1a [2] 18 0b [2] 56 07 [2] 5a 0d [2] 4d 06 [2] 56 48 [2] 6b }

  condition:
    any of them
}