rule TTP_XOR_MULT_DOSStub_c47b {
  strings:
    $key_c47b = { 90 13 [2] e4 0b [2] a3 09 [2] e4 18 [2] aa 14 [2] a6 1e [2] b1 15 [2] aa 5b [2] 97 }

  condition:
    any of them
}