rule TTP_XOR_MULT_DOSStub_f5ba {
  strings:
    $key_f5ba = { a1 d2 [2] d5 ca [2] 92 c8 [2] d5 d9 [2] 9b d5 [2] 97 df [2] 80 d4 [2] 9b 9a [2] a6 }

  condition:
    any of them
}