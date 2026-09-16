rule TTP_XOR_MULT_DOSStub_c3ba {
  strings:
    $key_c3ba = { 97 d2 [2] e3 ca [2] a4 c8 [2] e3 d9 [2] ad d5 [2] a1 df [2] b6 d4 [2] ad 9a [2] 90 }

  condition:
    any of them
}