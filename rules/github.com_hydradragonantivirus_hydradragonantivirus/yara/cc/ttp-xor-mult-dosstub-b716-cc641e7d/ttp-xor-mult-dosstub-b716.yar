rule TTP_XOR_MULT_DOSStub_b716 {
  strings:
    $key_b716 = { e3 7e [2] 97 66 [2] d0 64 [2] 97 75 [2] d9 79 [2] d5 73 [2] c2 78 [2] d9 36 [2] e4 }

  condition:
    any of them
}