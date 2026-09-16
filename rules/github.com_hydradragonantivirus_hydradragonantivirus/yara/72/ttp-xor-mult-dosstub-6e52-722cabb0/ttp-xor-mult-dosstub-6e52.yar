rule TTP_XOR_MULT_DOSStub_6e52 {
  strings:
    $key_6e52 = { 3a 3a [2] 4e 22 [2] 09 20 [2] 4e 31 [2] 00 3d [2] 0c 37 [2] 1b 3c [2] 00 72 [2] 3d }

  condition:
    any of them
}