rule TTP_XOR_MULT_DOSStub_eabe {
  strings:
    $key_eabe = { be d6 [2] ca ce [2] 8d cc [2] ca dd [2] 84 d1 [2] 88 db [2] 9f d0 [2] 84 9e [2] b9 }

  condition:
    any of them
}