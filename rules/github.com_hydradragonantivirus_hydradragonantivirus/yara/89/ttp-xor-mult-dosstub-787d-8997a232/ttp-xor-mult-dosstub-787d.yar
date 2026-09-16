rule TTP_XOR_MULT_DOSStub_787d {
  strings:
    $key_787d = { 2c 15 [2] 58 0d [2] 1f 0f [2] 58 1e [2] 16 12 [2] 1a 18 [2] 0d 13 [2] 16 5d [2] 2b }

  condition:
    any of them
}