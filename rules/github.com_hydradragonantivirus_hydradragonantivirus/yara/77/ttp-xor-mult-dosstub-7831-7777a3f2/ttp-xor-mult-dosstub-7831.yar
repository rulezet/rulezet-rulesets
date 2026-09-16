rule TTP_XOR_MULT_DOSStub_7831 {
  strings:
    $key_7831 = { 2c 59 [2] 58 41 [2] 1f 43 [2] 58 52 [2] 16 5e [2] 1a 54 [2] 0d 5f [2] 16 11 [2] 2b }

  condition:
    any of them
}