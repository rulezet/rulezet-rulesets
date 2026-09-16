rule TTP_XOR_MULT_DOSStub_e55c {
  strings:
    $key_e55c = { b1 34 [2] c5 2c [2] 82 2e [2] c5 3f [2] 8b 33 [2] 87 39 [2] 90 32 [2] 8b 7c [2] b6 }

  condition:
    any of them
}