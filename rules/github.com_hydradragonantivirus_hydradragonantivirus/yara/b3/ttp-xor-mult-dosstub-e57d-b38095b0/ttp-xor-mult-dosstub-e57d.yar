rule TTP_XOR_MULT_DOSStub_e57d {
  strings:
    $key_e57d = { b1 15 [2] c5 0d [2] 82 0f [2] c5 1e [2] 8b 12 [2] 87 18 [2] 90 13 [2] 8b 5d [2] b6 }

  condition:
    any of them
}