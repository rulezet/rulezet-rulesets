rule TTP_XOR_MULT_DOSStub_bf37 {
  strings:
    $key_bf37 = { eb 5f [2] 9f 47 [2] d8 45 [2] 9f 54 [2] d1 58 [2] dd 52 [2] ca 59 [2] d1 17 [2] ec }

  condition:
    any of them
}