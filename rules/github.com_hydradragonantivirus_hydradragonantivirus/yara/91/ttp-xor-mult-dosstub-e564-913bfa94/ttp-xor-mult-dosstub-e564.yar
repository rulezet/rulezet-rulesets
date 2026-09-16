rule TTP_XOR_MULT_DOSStub_e564 {
  strings:
    $key_e564 = { b1 0c [2] c5 14 [2] 82 16 [2] c5 07 [2] 8b 0b [2] 87 01 [2] 90 0a [2] 8b 44 [2] b6 }

  condition:
    any of them
}