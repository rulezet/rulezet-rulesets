rule TTP_XOR_MULT_DOSStub_7900 {
  strings:
    $key_7900 = { 2d 68 [2] 59 70 [2] 1e 72 [2] 59 63 [2] 17 6f [2] 1b 65 [2] 0c 6e [2] 17 20 [2] 2a }

  condition:
    any of them
}