rule TTP_XOR_MULT_DOSStub_7971 {
  strings:
    $key_7971 = { 2d 19 [2] 59 01 [2] 1e 03 [2] 59 12 [2] 17 1e [2] 1b 14 [2] 0c 1f [2] 17 51 [2] 2a }

  condition:
    any of them
}