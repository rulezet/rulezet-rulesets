rule TTP_XOR_MULT_DOSStub_bc7a {
  strings:
    $key_bc7a = { e8 12 [2] 9c 0a [2] db 08 [2] 9c 19 [2] d2 15 [2] de 1f [2] c9 14 [2] d2 5a [2] ef }

  condition:
    any of them
}