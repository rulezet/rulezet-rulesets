rule TTP_XOR_MULT_DOSStub_e528 {
  strings:
    $key_e528 = { b1 40 [2] c5 58 [2] 82 5a [2] c5 4b [2] 8b 47 [2] 87 4d [2] 90 46 [2] 8b 08 [2] b6 }

  condition:
    any of them
}