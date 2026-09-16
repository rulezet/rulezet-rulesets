rule TTP_XOR_MULT_DOSStub_bc7c {
  strings:
    $key_bc7c = { e8 14 [2] 9c 0c [2] db 0e [2] 9c 1f [2] d2 13 [2] de 19 [2] c9 12 [2] d2 5c [2] ef }

  condition:
    any of them
}