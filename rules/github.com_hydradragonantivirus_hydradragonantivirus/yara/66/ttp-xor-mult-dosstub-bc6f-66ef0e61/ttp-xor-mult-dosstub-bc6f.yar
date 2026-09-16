rule TTP_XOR_MULT_DOSStub_bc6f {
  strings:
    $key_bc6f = { e8 07 [2] 9c 1f [2] db 1d [2] 9c 0c [2] d2 00 [2] de 0a [2] c9 01 [2] d2 4f [2] ef }

  condition:
    any of them
}