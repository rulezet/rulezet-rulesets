rule TTP_XOR_MULT_DOSStub_bfce {
  strings:
    $key_bfce = { eb a6 [2] 9f be [2] d8 bc [2] 9f ad [2] d1 a1 [2] dd ab [2] ca a0 [2] d1 ee [2] ec }

  condition:
    any of them
}