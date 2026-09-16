rule TTP_XOR_MULT_DOSStub_f101 {
  strings:
    $key_f101 = { a5 69 [2] d1 71 [2] 96 73 [2] d1 62 [2] 9f 6e [2] 93 64 [2] 84 6f [2] 9f 21 [2] a2 }

  condition:
    any of them
}