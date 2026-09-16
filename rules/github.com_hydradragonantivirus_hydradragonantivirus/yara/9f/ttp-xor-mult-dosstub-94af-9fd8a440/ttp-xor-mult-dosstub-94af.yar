rule TTP_XOR_MULT_DOSStub_94af {
  strings:
    $key_94af = { c0 c7 [2] b4 df [2] f3 dd [2] b4 cc [2] fa c0 [2] f6 ca [2] e1 c1 [2] fa 8f [2] c7 }

  condition:
    any of them
}