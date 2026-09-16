rule TTP_XOR_MULT_DOSStub_6e68 {
  strings:
    $key_6e68 = { 3a 00 [2] 4e 18 [2] 09 1a [2] 4e 0b [2] 00 07 [2] 0c 0d [2] 1b 06 [2] 00 48 [2] 3d }

  condition:
    any of them
}