rule TTP_XOR_MULT_DOSStub_6851 {
  strings:
    $key_6851 = { 3c 39 [2] 48 21 [2] 0f 23 [2] 48 32 [2] 06 3e [2] 0a 34 [2] 1d 3f [2] 06 71 [2] 3b }

  condition:
    any of them
}