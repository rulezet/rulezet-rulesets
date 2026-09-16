rule TTP_XOR_MULT_DOSStub_3bb0 {
  strings:
    $key_3bb0 = { 6f d8 [2] 1b c0 [2] 5c c2 [2] 1b d3 [2] 55 df [2] 59 d5 [2] 4e de [2] 55 90 [2] 68 }

  condition:
    any of them
}