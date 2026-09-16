rule TTP_XOR_MULT_DOSStub_e2e0 {
  strings:
    $key_e2e0 = { b6 88 [2] c2 90 [2] 85 92 [2] c2 83 [2] 8c 8f [2] 80 85 [2] 97 8e [2] 8c c0 [2] b1 }

  condition:
    any of them
}