rule TTP_XOR_MULT_DOSStub_3c5d {
  strings:
    $key_3c5d = { 68 35 [2] 1c 2d [2] 5b 2f [2] 1c 3e [2] 52 32 [2] 5e 38 [2] 49 33 [2] 52 7d [2] 6f }

  condition:
    any of them
}