rule TTP_XOR_MULT_DOSStub_e50b {
  strings:
    $key_e50b = { b1 63 [2] c5 7b [2] 82 79 [2] c5 68 [2] 8b 64 [2] 87 6e [2] 90 65 [2] 8b 2b [2] b6 }

  condition:
    any of them
}