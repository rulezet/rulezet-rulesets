rule TTP_XOR_MULT_DOSStub_bf0f {
  strings:
    $key_bf0f = { eb 67 [2] 9f 7f [2] d8 7d [2] 9f 6c [2] d1 60 [2] dd 6a [2] ca 61 [2] d1 2f [2] ec }

  condition:
    any of them
}