rule TTP_XOR_MULT_DOSStub_bc23 {
  strings:
    $key_bc23 = { e8 4b [2] 9c 53 [2] db 51 [2] 9c 40 [2] d2 4c [2] de 46 [2] c9 4d [2] d2 03 [2] ef }

  condition:
    any of them
}