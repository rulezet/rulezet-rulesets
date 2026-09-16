rule TTP_XOR_MULT_DOSStub_6e74 {
  strings:
    $key_6e74 = { 3a 1c [2] 4e 04 [2] 09 06 [2] 4e 17 [2] 00 1b [2] 0c 11 [2] 1b 1a [2] 00 54 [2] 3d }

  condition:
    any of them
}