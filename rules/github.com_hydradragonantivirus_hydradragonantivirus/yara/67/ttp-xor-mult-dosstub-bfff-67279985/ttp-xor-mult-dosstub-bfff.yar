rule TTP_XOR_MULT_DOSStub_bfff {
  strings:
    $key_bfff = { eb 97 [2] 9f 8f [2] d8 8d [2] 9f 9c [2] d1 90 [2] dd 9a [2] ca 91 [2] d1 df [2] ec }

  condition:
    any of them
}