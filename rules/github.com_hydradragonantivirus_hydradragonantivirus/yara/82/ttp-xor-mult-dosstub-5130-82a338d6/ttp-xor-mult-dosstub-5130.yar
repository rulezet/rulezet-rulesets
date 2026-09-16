rule TTP_XOR_MULT_DOSStub_5130 {
  strings:
    $key_5130 = { 05 58 [2] 71 40 [2] 36 42 [2] 71 53 [2] 3f 5f [2] 33 55 [2] 24 5e [2] 3f 10 [2] 02 }

  condition:
    any of them
}