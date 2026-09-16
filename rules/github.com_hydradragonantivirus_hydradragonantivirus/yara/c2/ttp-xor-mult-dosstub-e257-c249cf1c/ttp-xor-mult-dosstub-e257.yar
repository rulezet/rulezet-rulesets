rule TTP_XOR_MULT_DOSStub_e257 {
  strings:
    $key_e257 = { b6 3f [2] c2 27 [2] 85 25 [2] c2 34 [2] 8c 38 [2] 80 32 [2] 97 39 [2] 8c 77 [2] b1 }

  condition:
    any of them
}