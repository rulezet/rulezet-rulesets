rule TTP_XOR_MULT_DOSStub_e25b {
  strings:
    $key_e25b = { b6 33 [2] c2 2b [2] 85 29 [2] c2 38 [2] 8c 34 [2] 80 3e [2] 97 35 [2] 8c 7b [2] b1 }

  condition:
    any of them
}