rule TTP_XOR_MULT_DOSStub_e02c {
  strings:
    $key_e02c = { b4 44 [2] c0 5c [2] 87 5e [2] c0 4f [2] 8e 43 [2] 82 49 [2] 95 42 [2] 8e 0c [2] b3 }

  condition:
    any of them
}