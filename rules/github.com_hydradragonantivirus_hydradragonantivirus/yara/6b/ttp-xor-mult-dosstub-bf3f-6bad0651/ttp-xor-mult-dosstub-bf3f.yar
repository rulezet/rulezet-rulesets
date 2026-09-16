rule TTP_XOR_MULT_DOSStub_bf3f {
  strings:
    $key_bf3f = { eb 57 [2] 9f 4f [2] d8 4d [2] 9f 5c [2] d1 50 [2] dd 5a [2] ca 51 [2] d1 1f [2] ec }

  condition:
    any of them
}