rule TTP_XOR_MULT_DOSStub_bf0b {
  strings:
    $key_bf0b = { eb 63 [2] 9f 7b [2] d8 79 [2] 9f 68 [2] d1 64 [2] dd 6e [2] ca 65 [2] d1 2b [2] ec }

  condition:
    any of them
}