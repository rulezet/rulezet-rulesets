rule TTP_XOR_MULT_DOSStub_e25c {
  strings:
    $key_e25c = { b6 34 [2] c2 2c [2] 85 2e [2] c2 3f [2] 8c 33 [2] 80 39 [2] 97 32 [2] 8c 7c [2] b1 }

  condition:
    any of them
}