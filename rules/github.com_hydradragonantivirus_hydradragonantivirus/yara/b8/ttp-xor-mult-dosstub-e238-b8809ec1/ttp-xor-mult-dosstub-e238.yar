rule TTP_XOR_MULT_DOSStub_e238 {
  strings:
    $key_e238 = { b6 50 [2] c2 48 [2] 85 4a [2] c2 5b [2] 8c 57 [2] 80 5d [2] 97 56 [2] 8c 18 [2] b1 }

  condition:
    any of them
}