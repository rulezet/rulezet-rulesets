rule TTP_XOR_MULT_DOSStub_e55b {
  strings:
    $key_e55b = { b1 33 [2] c5 2b [2] 82 29 [2] c5 38 [2] 8b 34 [2] 87 3e [2] 90 35 [2] 8b 7b [2] b6 }

  condition:
    any of them
}