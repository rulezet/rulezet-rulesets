rule TTP_XOR_MULT_DOSStub_7807 {
  strings:
    $key_7807 = { 2c 6f [2] 58 77 [2] 1f 75 [2] 58 64 [2] 16 68 [2] 1a 62 [2] 0d 69 [2] 16 27 [2] 2b }

  condition:
    any of them
}