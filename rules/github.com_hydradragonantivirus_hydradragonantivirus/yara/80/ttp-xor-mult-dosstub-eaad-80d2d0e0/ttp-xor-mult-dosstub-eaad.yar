rule TTP_XOR_MULT_DOSStub_eaad {
  strings:
    $key_eaad = { be c5 [2] ca dd [2] 8d df [2] ca ce [2] 84 c2 [2] 88 c8 [2] 9f c3 [2] 84 8d [2] b9 }

  condition:
    any of them
}