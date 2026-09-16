rule TTP_XOR_MULT_DOSStub_793d {
  strings:
    $key_793d = { 2d 55 [2] 59 4d [2] 1e 4f [2] 59 5e [2] 17 52 [2] 1b 58 [2] 0c 53 [2] 17 1d [2] 2a }

  condition:
    any of them
}