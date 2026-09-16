rule TTP_XOR_MULT_DOSStub_e5ba {
  strings:
    $key_e5ba = { b1 d2 [2] c5 ca [2] 82 c8 [2] c5 d9 [2] 8b d5 [2] 87 df [2] 90 d4 [2] 8b 9a [2] b6 }

  condition:
    any of them
}