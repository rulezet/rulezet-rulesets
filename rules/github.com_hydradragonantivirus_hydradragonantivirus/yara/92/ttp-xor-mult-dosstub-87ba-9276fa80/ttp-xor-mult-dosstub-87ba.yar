rule TTP_XOR_MULT_DOSStub_87ba {
  strings:
    $key_87ba = { d3 d2 [2] a7 ca [2] e0 c8 [2] a7 d9 [2] e9 d5 [2] e5 df [2] f2 d4 [2] e9 9a [2] d4 }

  condition:
    any of them
}