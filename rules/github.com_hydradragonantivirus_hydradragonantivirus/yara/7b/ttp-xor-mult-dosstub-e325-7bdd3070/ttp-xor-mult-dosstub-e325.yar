rule TTP_XOR_MULT_DOSStub_e325 {
  strings:
    $key_e325 = { b7 4d [2] c3 55 [2] 84 57 [2] c3 46 [2] 8d 4a [2] 81 40 [2] 96 4b [2] 8d 05 [2] b0 }

  condition:
    any of them
}