rule TTP_XOR_MULT_DOSStub_c24b {
  strings:
    $key_c24b = { 96 23 [2] e2 3b [2] a5 39 [2] e2 28 [2] ac 24 [2] a0 2e [2] b7 25 [2] ac 6b [2] 91 }

  condition:
    any of them
}