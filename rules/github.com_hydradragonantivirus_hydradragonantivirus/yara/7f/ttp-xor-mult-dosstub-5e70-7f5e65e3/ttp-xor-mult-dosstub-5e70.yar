rule TTP_XOR_MULT_DOSStub_5e70 {
  strings:
    $key_5e70 = { 0a 18 [2] 7e 00 [2] 39 02 [2] 7e 13 [2] 30 1f [2] 3c 15 [2] 2b 1e [2] 30 50 [2] 0d }

  condition:
    any of them
}