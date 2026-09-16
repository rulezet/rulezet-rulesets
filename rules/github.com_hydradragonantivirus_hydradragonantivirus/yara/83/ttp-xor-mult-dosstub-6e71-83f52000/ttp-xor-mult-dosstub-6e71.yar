rule TTP_XOR_MULT_DOSStub_6e71 {
  strings:
    $key_6e71 = { 3a 19 [2] 4e 01 [2] 09 03 [2] 4e 12 [2] 00 1e [2] 0c 14 [2] 1b 1f [2] 00 51 [2] 3d }

  condition:
    any of them
}