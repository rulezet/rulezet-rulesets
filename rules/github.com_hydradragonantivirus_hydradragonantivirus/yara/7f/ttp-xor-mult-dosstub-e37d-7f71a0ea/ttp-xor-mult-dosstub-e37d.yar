rule TTP_XOR_MULT_DOSStub_e37d {
  strings:
    $key_e37d = { b7 15 [2] c3 0d [2] 84 0f [2] c3 1e [2] 8d 12 [2] 81 18 [2] 96 13 [2] 8d 5d [2] b0 }

  condition:
    any of them
}