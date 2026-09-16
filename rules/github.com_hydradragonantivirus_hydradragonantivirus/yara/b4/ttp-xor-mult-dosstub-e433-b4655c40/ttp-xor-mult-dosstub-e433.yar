rule TTP_XOR_MULT_DOSStub_e433 {
  strings:
    $key_e433 = { b0 5b [2] c4 43 [2] 83 41 [2] c4 50 [2] 8a 5c [2] 86 56 [2] 91 5d [2] 8a 13 [2] b7 }

  condition:
    any of them
}