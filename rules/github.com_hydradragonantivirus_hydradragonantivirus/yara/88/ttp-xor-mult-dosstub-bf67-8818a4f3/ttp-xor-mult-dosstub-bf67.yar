rule TTP_XOR_MULT_DOSStub_bf67 {
  strings:
    $key_bf67 = { eb 0f [2] 9f 17 [2] d8 15 [2] 9f 04 [2] d1 08 [2] dd 02 [2] ca 09 [2] d1 47 [2] ec }

  condition:
    any of them
}