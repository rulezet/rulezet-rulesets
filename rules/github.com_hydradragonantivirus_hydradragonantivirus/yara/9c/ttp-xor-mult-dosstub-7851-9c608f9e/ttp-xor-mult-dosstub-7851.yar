rule TTP_XOR_MULT_DOSStub_7851 {
  strings:
    $key_7851 = { 2c 39 [2] 58 21 [2] 1f 23 [2] 58 32 [2] 16 3e [2] 1a 34 [2] 0d 3f [2] 16 71 [2] 2b }

  condition:
    any of them
}