rule TTP_XOR_MULT_DOSStub_c2e0 {
  strings:
    $key_c2e0 = { 96 88 [2] e2 90 [2] a5 92 [2] e2 83 [2] ac 8f [2] a0 85 [2] b7 8e [2] ac c0 [2] 91 }

  condition:
    any of them
}