rule TTP_XOR_MULT_DOSStub_e1ba {
  strings:
    $key_e1ba = { b5 d2 [2] c1 ca [2] 86 c8 [2] c1 d9 [2] 8f d5 [2] 83 df [2] 94 d4 [2] 8f 9a [2] b2 }

  condition:
    any of them
}