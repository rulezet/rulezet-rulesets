rule TTP_XOR_MULT_DOSStub_e525 {
  strings:
    $key_e525 = { b1 4d [2] c5 55 [2] 82 57 [2] c5 46 [2] 8b 4a [2] 87 40 [2] 90 4b [2] 8b 05 [2] b6 }

  condition:
    any of them
}