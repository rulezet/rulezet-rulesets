rule TTP_XOR_MULT_DOSStub_7836 {
  strings:
    $key_7836 = { 2c 5e [2] 58 46 [2] 1f 44 [2] 58 55 [2] 16 59 [2] 1a 53 [2] 0d 58 [2] 16 16 [2] 2b }

  condition:
    any of them
}