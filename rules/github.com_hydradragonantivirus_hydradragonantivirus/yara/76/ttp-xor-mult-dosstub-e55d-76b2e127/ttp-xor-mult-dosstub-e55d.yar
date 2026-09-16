rule TTP_XOR_MULT_DOSStub_e55d {
  strings:
    $key_e55d = { b1 35 [2] c5 2d [2] 82 2f [2] c5 3e [2] 8b 32 [2] 87 38 [2] 90 33 [2] 8b 7d [2] b6 }

  condition:
    any of them
}