rule TTP_XOR_MULT_DOSStub_bcff {
  strings:
    $key_bcff = { e8 97 [2] 9c 8f [2] db 8d [2] 9c 9c [2] d2 90 [2] de 9a [2] c9 91 [2] d2 df [2] ef }

  condition:
    any of them
}