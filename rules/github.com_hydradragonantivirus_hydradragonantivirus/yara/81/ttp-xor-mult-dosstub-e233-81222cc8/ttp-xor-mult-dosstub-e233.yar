rule TTP_XOR_MULT_DOSStub_e233 {
  strings:
    $key_e233 = { b6 5b [2] c2 43 [2] 85 41 [2] c2 50 [2] 8c 5c [2] 80 56 [2] 97 5d [2] 8c 13 [2] b1 }

  condition:
    any of them
}