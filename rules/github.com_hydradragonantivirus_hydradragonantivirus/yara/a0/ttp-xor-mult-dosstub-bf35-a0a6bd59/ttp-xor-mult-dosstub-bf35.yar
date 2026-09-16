rule TTP_XOR_MULT_DOSStub_bf35 {
  strings:
    $key_bf35 = { eb 5d [2] 9f 45 [2] d8 47 [2] 9f 56 [2] d1 5a [2] dd 50 [2] ca 5b [2] d1 15 [2] ec }

  condition:
    any of them
}