rule TTP_XOR_MULT_DOSStub_e77b {
  strings:
    $key_e77b = { b3 13 [2] c7 0b [2] 80 09 [2] c7 18 [2] 89 14 [2] 85 1e [2] 92 15 [2] 89 5b [2] b4 }

  condition:
    any of them
}