rule TTP_XOR_MULT_DOSStub_6e40 {
  strings:
    $key_6e40 = { 3a 28 [2] 4e 30 [2] 09 32 [2] 4e 23 [2] 00 2f [2] 0c 25 [2] 1b 2e [2] 00 60 [2] 3d }

  condition:
    any of them
}