rule TTP_XOR_MULT_DOSStub_bf6c {
  strings:
    $key_bf6c = { eb 04 [2] 9f 1c [2] d8 1e [2] 9f 0f [2] d1 03 [2] dd 09 [2] ca 02 [2] d1 4c [2] ec }

  condition:
    any of them
}