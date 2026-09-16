rule TTP_XOR_MULT_DOSStub_83af {
  strings:
    $key_83af = { d7 c7 [2] a3 df [2] e4 dd [2] a3 cc [2] ed c0 [2] e1 ca [2] f6 c1 [2] ed 8f [2] d0 }

  condition:
    any of them
}