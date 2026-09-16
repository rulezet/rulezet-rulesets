rule TTP_XOR_MULT_DOSStub_e535 {
  strings:
    $key_e535 = { b1 5d [2] c5 45 [2] 82 47 [2] c5 56 [2] 8b 5a [2] 87 50 [2] 90 5b [2] 8b 15 [2] b6 }

  condition:
    any of them
}