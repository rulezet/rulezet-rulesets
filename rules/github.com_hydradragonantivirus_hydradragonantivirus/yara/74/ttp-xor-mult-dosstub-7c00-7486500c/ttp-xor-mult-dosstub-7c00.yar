rule TTP_XOR_MULT_DOSStub_7c00 {
  strings:
    $key_7c00 = { 28 68 [2] 5c 70 [2] 1b 72 [2] 5c 63 [2] 12 6f [2] 1e 65 [2] 09 6e [2] 12 20 [2] 2f }

  condition:
    any of them
}