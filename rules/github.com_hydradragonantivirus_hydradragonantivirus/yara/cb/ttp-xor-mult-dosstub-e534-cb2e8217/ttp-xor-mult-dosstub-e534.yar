rule TTP_XOR_MULT_DOSStub_e534 {
  strings:
    $key_e534 = { b1 5c [2] c5 44 [2] 82 46 [2] c5 57 [2] 8b 5b [2] 87 51 [2] 90 5a [2] 8b 14 [2] b6 }

  condition:
    any of them
}