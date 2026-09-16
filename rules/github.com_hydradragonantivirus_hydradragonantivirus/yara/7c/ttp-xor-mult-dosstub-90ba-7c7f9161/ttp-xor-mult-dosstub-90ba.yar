rule TTP_XOR_MULT_DOSStub_90ba {
  strings:
    $key_90ba = { c4 d2 [2] b0 ca [2] f7 c8 [2] b0 d9 [2] fe d5 [2] f2 df [2] e5 d4 [2] fe 9a [2] c3 }

  condition:
    any of them
}