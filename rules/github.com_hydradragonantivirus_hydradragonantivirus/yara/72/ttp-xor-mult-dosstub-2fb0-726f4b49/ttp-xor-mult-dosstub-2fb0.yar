rule TTP_XOR_MULT_DOSStub_2fb0 {
  strings:
    $key_2fb0 = { 7b d8 [2] 0f c0 [2] 48 c2 [2] 0f d3 [2] 41 df [2] 4d d5 [2] 5a de [2] 41 90 [2] 7c }

  condition:
    any of them
}