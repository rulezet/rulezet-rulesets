rule TTP_XOR_MULT_DOSStub_bf3c {
  strings:
    $key_bf3c = { eb 54 [2] 9f 4c [2] d8 4e [2] 9f 5f [2] d1 53 [2] dd 59 [2] ca 52 [2] d1 1c [2] ec }

  condition:
    any of them
}