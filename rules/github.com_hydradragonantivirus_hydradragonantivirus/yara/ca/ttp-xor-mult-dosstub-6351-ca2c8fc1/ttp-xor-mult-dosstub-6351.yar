rule TTP_XOR_MULT_DOSStub_6351 {
  strings:
    $key_6351 = { 37 39 [2] 43 21 [2] 04 23 [2] 43 32 [2] 0d 3e [2] 01 34 [2] 16 3f [2] 0d 71 [2] 30 }

  condition:
    any of them
}