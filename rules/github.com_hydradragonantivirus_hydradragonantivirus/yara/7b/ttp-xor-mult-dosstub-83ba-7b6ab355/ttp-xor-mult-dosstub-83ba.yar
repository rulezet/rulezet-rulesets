rule TTP_XOR_MULT_DOSStub_83ba {
  strings:
    $key_83ba = { d7 d2 [2] a3 ca [2] e4 c8 [2] a3 d9 [2] ed d5 [2] e1 df [2] f6 d4 [2] ed 9a [2] d0 }

  condition:
    any of them
}