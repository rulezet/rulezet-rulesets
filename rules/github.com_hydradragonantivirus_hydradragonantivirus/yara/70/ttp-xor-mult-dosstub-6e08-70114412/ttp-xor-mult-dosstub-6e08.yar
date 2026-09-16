rule TTP_XOR_MULT_DOSStub_6e08 {
  strings:
    $key_6e08 = { 3a 60 [2] 4e 78 [2] 09 7a [2] 4e 6b [2] 00 67 [2] 0c 6d [2] 1b 66 [2] 00 28 [2] 3d }

  condition:
    any of them
}