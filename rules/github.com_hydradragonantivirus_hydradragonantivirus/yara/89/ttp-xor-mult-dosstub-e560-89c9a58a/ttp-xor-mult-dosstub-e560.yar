rule TTP_XOR_MULT_DOSStub_e560 {
  strings:
    $key_e560 = { b1 08 [2] c5 10 [2] 82 12 [2] c5 03 [2] 8b 0f [2] 87 05 [2] 90 0e [2] 8b 40 [2] b6 }

  condition:
    any of them
}