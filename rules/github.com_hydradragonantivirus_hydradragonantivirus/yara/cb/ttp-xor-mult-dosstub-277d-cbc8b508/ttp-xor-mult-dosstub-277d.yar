rule TTP_XOR_MULT_DOSStub_277d {
  strings:
    $key_277d = { 73 15 [2] 07 0d [2] 40 0f [2] 07 1e [2] 49 12 [2] 45 18 [2] 52 13 [2] 49 5d [2] 74 }

  condition:
    any of them
}