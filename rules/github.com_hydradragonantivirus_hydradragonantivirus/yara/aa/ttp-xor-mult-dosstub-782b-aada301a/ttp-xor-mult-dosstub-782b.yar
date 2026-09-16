rule TTP_XOR_MULT_DOSStub_782b {
  strings:
    $key_782b = { 2c 43 [2] 58 5b [2] 1f 59 [2] 58 48 [2] 16 44 [2] 1a 4e [2] 0d 45 [2] 16 0b [2] 2b }

  condition:
    any of them
}