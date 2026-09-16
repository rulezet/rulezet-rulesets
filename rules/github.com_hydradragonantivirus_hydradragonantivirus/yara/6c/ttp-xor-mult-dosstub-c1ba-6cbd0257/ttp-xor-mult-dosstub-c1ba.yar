rule TTP_XOR_MULT_DOSStub_c1ba {
  strings:
    $key_c1ba = { 95 d2 [2] e1 ca [2] a6 c8 [2] e1 d9 [2] af d5 [2] a3 df [2] b4 d4 [2] af 9a [2] 92 }

  condition:
    any of them
}