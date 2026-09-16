rule TTP_XOR_MULT_DOSStub_7251 {
  strings:
    $key_7251 = { 26 39 [2] 52 21 [2] 15 23 [2] 52 32 [2] 1c 3e [2] 10 34 [2] 07 3f [2] 1c 71 [2] 21 }

  condition:
    any of them
}