rule TTP_XOR_MULT_DOSStub_e57b {
  strings:
    $key_e57b = { b1 13 [2] c5 0b [2] 82 09 [2] c5 18 [2] 8b 14 [2] 87 1e [2] 90 15 [2] 8b 5b [2] b6 }

  condition:
    any of them
}