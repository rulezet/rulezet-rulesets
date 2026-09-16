rule TTP_XOR_MULT_DOSStub_e77d {
  strings:
    $key_e77d = { b3 15 [2] c7 0d [2] 80 0f [2] c7 1e [2] 89 12 [2] 85 18 [2] 92 13 [2] 89 5d [2] b4 }

  condition:
    any of them
}