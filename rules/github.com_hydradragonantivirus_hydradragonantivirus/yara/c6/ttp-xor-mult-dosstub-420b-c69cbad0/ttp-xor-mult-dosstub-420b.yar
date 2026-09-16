rule TTP_XOR_MULT_DOSStub_420b {
  strings:
    $key_420b = { 16 63 [2] 62 7b [2] 25 79 [2] 62 68 [2] 2c 64 [2] 20 6e [2] 37 65 [2] 2c 2b [2] 11 }

  condition:
    any of them
}