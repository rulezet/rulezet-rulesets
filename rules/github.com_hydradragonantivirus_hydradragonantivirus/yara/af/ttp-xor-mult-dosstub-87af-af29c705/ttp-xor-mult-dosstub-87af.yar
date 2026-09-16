rule TTP_XOR_MULT_DOSStub_87af {
  strings:
    $key_87af = { d3 c7 [2] a7 df [2] e0 dd [2] a7 cc [2] e9 c0 [2] e5 ca [2] f2 c1 [2] e9 8f [2] d4 }

  condition:
    any of them
}