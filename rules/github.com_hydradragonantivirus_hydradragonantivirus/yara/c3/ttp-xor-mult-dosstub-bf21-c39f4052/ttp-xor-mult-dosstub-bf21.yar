rule TTP_XOR_MULT_DOSStub_bf21 {
  strings:
    $key_bf21 = { eb 49 [2] 9f 51 [2] d8 53 [2] 9f 42 [2] d1 4e [2] dd 44 [2] ca 4f [2] d1 01 [2] ec }

  condition:
    any of them
}