rule TTP_XOR_MULT_DOSStub_e502 {
  strings:
    $key_e502 = { b1 6a [2] c5 72 [2] 82 70 [2] c5 61 [2] 8b 6d [2] 87 67 [2] 90 6c [2] 8b 22 [2] b6 }

  condition:
    any of them
}