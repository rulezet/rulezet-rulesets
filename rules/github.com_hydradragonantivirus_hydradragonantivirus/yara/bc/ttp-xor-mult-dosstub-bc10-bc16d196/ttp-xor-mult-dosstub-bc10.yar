rule TTP_XOR_MULT_DOSStub_bc10 {
  strings:
    $key_bc10 = { e8 78 [2] 9c 60 [2] db 62 [2] 9c 73 [2] d2 7f [2] de 75 [2] c9 7e [2] d2 30 [2] ef }

  condition:
    any of them
}