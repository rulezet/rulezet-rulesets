rule TTP_XOR_MULT_DOSStub_6e78 {
  strings:
    $key_6e78 = { 3a 10 [2] 4e 08 [2] 09 0a [2] 4e 1b [2] 00 17 [2] 0c 1d [2] 1b 16 [2] 00 58 [2] 3d }

  condition:
    any of them
}