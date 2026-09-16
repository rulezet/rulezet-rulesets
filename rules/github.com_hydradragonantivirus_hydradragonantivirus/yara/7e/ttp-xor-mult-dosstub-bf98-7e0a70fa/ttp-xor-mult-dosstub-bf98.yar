rule TTP_XOR_MULT_DOSStub_bf98 {
  strings:
    $key_bf98 = { eb f0 [2] 9f e8 [2] d8 ea [2] 9f fb [2] d1 f7 [2] dd fd [2] ca f6 [2] d1 b8 [2] ec }

  condition:
    any of them
}