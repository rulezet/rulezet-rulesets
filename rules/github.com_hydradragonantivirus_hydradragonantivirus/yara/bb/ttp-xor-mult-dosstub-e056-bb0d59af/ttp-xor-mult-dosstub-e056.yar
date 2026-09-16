rule TTP_XOR_MULT_DOSStub_e056 {
  strings:
    $key_e056 = { b4 3e [2] c0 26 [2] 87 24 [2] c0 35 [2] 8e 39 [2] 82 33 [2] 95 38 [2] 8e 76 [2] b3 }

  condition:
    any of them
}