rule TTP_XOR_MULT_DOSStub_bf0e {
  strings:
    $key_bf0e = { eb 66 [2] 9f 7e [2] d8 7c [2] 9f 6d [2] d1 61 [2] dd 6b [2] ca 60 [2] d1 2e [2] ec }

  condition:
    any of them
}