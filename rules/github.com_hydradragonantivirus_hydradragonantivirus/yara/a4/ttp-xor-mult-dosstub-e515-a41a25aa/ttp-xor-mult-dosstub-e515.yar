rule TTP_XOR_MULT_DOSStub_e515 {
  strings:
    $key_e515 = { b1 7d [2] c5 65 [2] 82 67 [2] c5 76 [2] 8b 7a [2] 87 70 [2] 90 7b [2] 8b 35 [2] b6 }

  condition:
    any of them
}