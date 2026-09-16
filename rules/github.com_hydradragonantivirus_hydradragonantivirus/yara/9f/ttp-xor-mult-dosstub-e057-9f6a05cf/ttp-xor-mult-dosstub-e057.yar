rule TTP_XOR_MULT_DOSStub_e057 {
  strings:
    $key_e057 = { b4 3f [2] c0 27 [2] 87 25 [2] c0 34 [2] 8e 38 [2] 82 32 [2] 95 39 [2] 8e 77 [2] b3 }

  condition:
    any of them
}