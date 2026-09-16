rule TTP_XOR_MULT_DOSStub_7451 {
  strings:
    $key_7451 = { 20 39 [2] 54 21 [2] 13 23 [2] 54 32 [2] 1a 3e [2] 16 34 [2] 01 3f [2] 1a 71 [2] 27 }

  condition:
    any of them
}