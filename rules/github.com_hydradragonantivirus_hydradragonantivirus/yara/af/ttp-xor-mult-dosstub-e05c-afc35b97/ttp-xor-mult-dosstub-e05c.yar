rule TTP_XOR_MULT_DOSStub_e05c {
  strings:
    $key_e05c = { b4 34 [2] c0 2c [2] 87 2e [2] c0 3f [2] 8e 33 [2] 82 39 [2] 95 32 [2] 8e 7c [2] b3 }

  condition:
    any of them
}