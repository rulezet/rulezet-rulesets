rule TTP_XOR_MULT_DOSStub_2bb0 {
  strings:
    $key_2bb0 = { 7f d8 [2] 0b c0 [2] 4c c2 [2] 0b d3 [2] 45 df [2] 49 d5 [2] 5e de [2] 45 90 [2] 78 }

  condition:
    any of them
}