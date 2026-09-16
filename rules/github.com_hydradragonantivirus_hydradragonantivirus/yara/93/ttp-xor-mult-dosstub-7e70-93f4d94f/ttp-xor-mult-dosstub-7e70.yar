rule TTP_XOR_MULT_DOSStub_7e70 {
  strings:
    $key_7e70 = { 2a 18 [2] 5e 00 [2] 19 02 [2] 5e 13 [2] 10 1f [2] 1c 15 [2] 0b 1e [2] 10 50 [2] 2d }

  condition:
    any of them
}