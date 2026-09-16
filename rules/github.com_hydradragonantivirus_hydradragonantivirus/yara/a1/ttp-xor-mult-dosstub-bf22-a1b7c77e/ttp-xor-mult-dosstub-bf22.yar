rule TTP_XOR_MULT_DOSStub_bf22 {
  strings:
    $key_bf22 = { eb 4a [2] 9f 52 [2] d8 50 [2] 9f 41 [2] d1 4d [2] dd 47 [2] ca 4c [2] d1 02 [2] ec }

  condition:
    any of them
}