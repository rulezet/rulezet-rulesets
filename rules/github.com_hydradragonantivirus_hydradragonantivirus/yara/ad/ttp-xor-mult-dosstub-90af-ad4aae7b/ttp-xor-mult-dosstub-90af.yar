rule TTP_XOR_MULT_DOSStub_90af {
  strings:
    $key_90af = { c4 c7 [2] b0 df [2] f7 dd [2] b0 cc [2] fe c0 [2] f2 ca [2] e5 c1 [2] fe 8f [2] c3 }

  condition:
    any of them
}