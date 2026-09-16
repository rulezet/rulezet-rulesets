rule TTP_XOR_MULT_DOSStub_bfa8 {
  strings:
    $key_bfa8 = { eb c0 [2] 9f d8 [2] d8 da [2] 9f cb [2] d1 c7 [2] dd cd [2] ca c6 [2] d1 88 [2] ec }

  condition:
    any of them
}