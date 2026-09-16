rule TTP_XOR_MULT_DOSStub_e538 {
  strings:
    $key_e538 = { b1 50 [2] c5 48 [2] 82 4a [2] c5 5b [2] 8b 57 [2] 87 5d [2] 90 56 [2] 8b 18 [2] b6 }

  condition:
    any of them
}