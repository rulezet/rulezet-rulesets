rule TTP_XOR_MULT_DOSStub_bf55 {
  strings:
    $key_bf55 = { eb 3d [2] 9f 25 [2] d8 27 [2] 9f 36 [2] d1 3a [2] dd 30 [2] ca 3b [2] d1 75 [2] ec }

  condition:
    any of them
}