rule TTP_XOR_MULT_DOSStub_781e {
  strings:
    $key_781e = { 2c 76 [2] 58 6e [2] 1f 6c [2] 58 7d [2] 16 71 [2] 1a 7b [2] 0d 70 [2] 16 3e [2] 2b }

  condition:
    any of them
}