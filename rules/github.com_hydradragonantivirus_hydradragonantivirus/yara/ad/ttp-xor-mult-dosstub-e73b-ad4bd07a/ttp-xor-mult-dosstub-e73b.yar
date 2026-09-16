rule TTP_XOR_MULT_DOSStub_e73b {
  strings:
    $key_e73b = { b3 53 [2] c7 4b [2] 80 49 [2] c7 58 [2] 89 54 [2] 85 5e [2] 92 55 [2] 89 1b [2] b4 }

  condition:
    any of them
}