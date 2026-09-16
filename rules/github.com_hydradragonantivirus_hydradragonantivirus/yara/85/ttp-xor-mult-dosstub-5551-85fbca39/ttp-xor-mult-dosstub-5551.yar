rule TTP_XOR_MULT_DOSStub_5551 {
  strings:
    $key_5551 = { 01 39 [2] 75 21 [2] 32 23 [2] 75 32 [2] 3b 3e [2] 37 34 [2] 20 3f [2] 3b 71 [2] 06 }

  condition:
    any of them
}