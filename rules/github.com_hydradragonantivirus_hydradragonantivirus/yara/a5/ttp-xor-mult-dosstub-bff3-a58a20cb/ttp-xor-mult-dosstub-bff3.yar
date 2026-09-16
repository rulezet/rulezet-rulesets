rule TTP_XOR_MULT_DOSStub_bff3 {
  strings:
    $key_bff3 = { eb 9b [2] 9f 83 [2] d8 81 [2] 9f 90 [2] d1 9c [2] dd 96 [2] ca 9d [2] d1 d3 [2] ec }

  condition:
    any of them
}