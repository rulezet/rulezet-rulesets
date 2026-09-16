rule TTP_XOR_MULT_DOSStub_bf91 {
  strings:
    $key_bf91 = { eb f9 [2] 9f e1 [2] d8 e3 [2] 9f f2 [2] d1 fe [2] dd f4 [2] ca ff [2] d1 b1 [2] ec }

  condition:
    any of them
}