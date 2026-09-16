rule TTP_XOR_MULT_DOSStub_e277 {
  strings:
    $key_e277 = { b6 1f [2] c2 07 [2] 85 05 [2] c2 14 [2] 8c 18 [2] 80 12 [2] 97 19 [2] 8c 57 [2] b1 }

  condition:
    any of them
}