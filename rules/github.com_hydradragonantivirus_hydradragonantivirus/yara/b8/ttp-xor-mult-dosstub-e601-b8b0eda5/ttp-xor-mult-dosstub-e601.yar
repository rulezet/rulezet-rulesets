rule TTP_XOR_MULT_DOSStub_e601 {
  strings:
    $key_e601 = { b2 69 [2] c6 71 [2] 81 73 [2] c6 62 [2] 88 6e [2] 84 64 [2] 93 6f [2] 88 21 [2] b5 }

  condition:
    any of them
}