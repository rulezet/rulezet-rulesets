rule TTP_XOR_MULT_DOSStub_5001 {
  strings:
    $key_5001 = { 04 69 [2] 70 71 [2] 37 73 [2] 70 62 [2] 3e 6e [2] 32 64 [2] 25 6f [2] 3e 21 [2] 03 }

  condition:
    any of them
}