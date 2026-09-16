rule TTP_XOR_MULT_DOSStub_94ba {
  strings:
    $key_94ba = { c0 d2 [2] b4 ca [2] f3 c8 [2] b4 d9 [2] fa d5 [2] f6 df [2] e1 d4 [2] fa 9a [2] c7 }

  condition:
    any of them
}