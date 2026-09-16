rule TTP_XOR_MULT_DOSStub_81af {
  strings:
    $key_81af = { d5 c7 [2] a1 df [2] e6 dd [2] a1 cc [2] ef c0 [2] e3 ca [2] f4 c1 [2] ef 8f [2] d2 }

  condition:
    any of them
}