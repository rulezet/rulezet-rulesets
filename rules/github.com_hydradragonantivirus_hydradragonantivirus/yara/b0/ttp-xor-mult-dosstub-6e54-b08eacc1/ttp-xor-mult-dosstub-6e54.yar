rule TTP_XOR_MULT_DOSStub_6e54 {
  strings:
    $key_6e54 = { 3a 3c [2] 4e 24 [2] 09 26 [2] 4e 37 [2] 00 3b [2] 0c 31 [2] 1b 3a [2] 00 74 [2] 3d }

  condition:
    any of them
}