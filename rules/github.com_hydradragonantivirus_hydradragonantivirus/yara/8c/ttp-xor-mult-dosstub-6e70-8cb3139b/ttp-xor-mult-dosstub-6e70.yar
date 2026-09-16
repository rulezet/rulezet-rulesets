rule TTP_XOR_MULT_DOSStub_6e70 {
  strings:
    $key_6e70 = { 3a 18 [2] 4e 00 [2] 09 02 [2] 4e 13 [2] 00 1f [2] 0c 15 [2] 1b 1e [2] 00 50 [2] 3d }

  condition:
    any of them
}