rule TTP_XOR_MULT_DOSStub_95af {
  strings:
    $key_95af = { c1 c7 [2] b5 df [2] f2 dd [2] b5 cc [2] fb c0 [2] f7 ca [2] e0 c1 [2] fb 8f [2] c6 }

  condition:
    any of them
}