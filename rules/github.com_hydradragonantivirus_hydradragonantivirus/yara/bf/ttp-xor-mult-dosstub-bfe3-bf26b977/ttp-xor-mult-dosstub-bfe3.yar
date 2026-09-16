rule TTP_XOR_MULT_DOSStub_bfe3 {
  strings:
    $key_bfe3 = { eb 8b [2] 9f 93 [2] d8 91 [2] 9f 80 [2] d1 8c [2] dd 86 [2] ca 8d [2] d1 c3 [2] ec }

  condition:
    any of them
}