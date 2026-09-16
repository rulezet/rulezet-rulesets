rule TTP_XOR_MULT_DOSStub_e34a {
  strings:
    $key_e34a = { b7 22 [2] c3 3a [2] 84 38 [2] c3 29 [2] 8d 25 [2] 81 2f [2] 96 24 [2] 8d 6a [2] b0 }

  condition:
    any of them
}