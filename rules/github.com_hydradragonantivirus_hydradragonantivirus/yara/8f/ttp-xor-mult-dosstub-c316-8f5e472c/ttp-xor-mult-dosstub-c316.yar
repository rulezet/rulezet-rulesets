rule TTP_XOR_MULT_DOSStub_c316 {
  strings:
    $key_c316 = { 97 7e [2] e3 66 [2] a4 64 [2] e3 75 [2] ad 79 [2] a1 73 [2] b6 78 [2] ad 36 [2] 90 }

  condition:
    any of them
}