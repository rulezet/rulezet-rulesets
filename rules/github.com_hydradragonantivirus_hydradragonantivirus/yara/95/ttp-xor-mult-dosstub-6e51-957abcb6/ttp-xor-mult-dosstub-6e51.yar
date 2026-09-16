rule TTP_XOR_MULT_DOSStub_6e51 {
  strings:
    $key_6e51 = { 3a 39 [2] 4e 21 [2] 09 23 [2] 4e 32 [2] 00 3e [2] 0c 34 [2] 1b 3f [2] 00 71 [2] 3d }

  condition:
    any of them
}