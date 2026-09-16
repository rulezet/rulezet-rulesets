rule TTP_XOR_MULT_DOSStub_7816 {
  strings:
    $key_7816 = { 2c 7e [2] 58 66 [2] 1f 64 [2] 58 75 [2] 16 79 [2] 1a 73 [2] 0d 78 [2] 16 36 [2] 2b }

  condition:
    any of them
}