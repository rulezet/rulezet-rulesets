rule TTP_XOR_MULT_DOSStub_e25d {
  strings:
    $key_e25d = { b6 35 [2] c2 2d [2] 85 2f [2] c2 3e [2] 8c 32 [2] 80 38 [2] 97 33 [2] 8c 7d [2] b1 }

  condition:
    any of them
}