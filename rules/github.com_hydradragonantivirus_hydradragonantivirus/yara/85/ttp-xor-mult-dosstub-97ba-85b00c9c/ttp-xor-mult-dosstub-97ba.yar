rule TTP_XOR_MULT_DOSStub_97ba {
  strings:
    $key_97ba = { c3 d2 [2] b7 ca [2] f0 c8 [2] b7 d9 [2] f9 d5 [2] f5 df [2] e2 d4 [2] f9 9a [2] c4 }

  condition:
    any of them
}