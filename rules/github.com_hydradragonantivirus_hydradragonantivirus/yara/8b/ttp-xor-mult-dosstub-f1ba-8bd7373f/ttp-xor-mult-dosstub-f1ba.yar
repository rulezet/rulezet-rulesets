rule TTP_XOR_MULT_DOSStub_f1ba {
  strings:
    $key_f1ba = { a5 d2 [2] d1 ca [2] 96 c8 [2] d1 d9 [2] 9f d5 [2] 93 df [2] 84 d4 [2] 9f 9a [2] a2 }

  condition:
    any of them
}