rule TTP_XOR_MULT_DOSStub_e54b {
  strings:
    $key_e54b = { b1 23 [2] c5 3b [2] 82 39 [2] c5 28 [2] 8b 24 [2] 87 2e [2] 90 25 [2] 8b 6b [2] b6 }

  condition:
    any of them
}