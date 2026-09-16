rule TTP_XOR_MULT_DOSStub_bc0f {
  strings:
    $key_bc0f = { e8 67 [2] 9c 7f [2] db 7d [2] 9c 6c [2] d2 60 [2] de 6a [2] c9 61 [2] d2 2f [2] ef }

  condition:
    any of them
}