rule TTP_XOR_MULT_DOSStub_783b {
  strings:
    $key_783b = { 2c 53 [2] 58 4b [2] 1f 49 [2] 58 58 [2] 16 54 [2] 1a 5e [2] 0d 55 [2] 16 1b [2] 2b }

  condition:
    any of them
}