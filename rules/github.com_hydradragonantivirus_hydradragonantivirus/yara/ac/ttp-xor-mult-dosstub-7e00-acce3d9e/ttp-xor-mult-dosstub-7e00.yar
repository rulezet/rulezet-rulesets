rule TTP_XOR_MULT_DOSStub_7e00 {
  strings:
    $key_7e00 = { 2a 68 [2] 5e 70 [2] 19 72 [2] 5e 63 [2] 10 6f [2] 1c 65 [2] 0b 6e [2] 10 20 [2] 2d }

  condition:
    any of them
}