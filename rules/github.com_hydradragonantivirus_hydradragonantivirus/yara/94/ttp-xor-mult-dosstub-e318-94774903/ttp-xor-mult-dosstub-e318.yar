rule TTP_XOR_MULT_DOSStub_e318 {
  strings:
    $key_e318 = { b7 70 [2] c3 68 [2] 84 6a [2] c3 7b [2] 8d 77 [2] 81 7d [2] 96 76 [2] 8d 38 [2] b0 }

  condition:
    any of them
}