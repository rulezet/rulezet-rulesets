rule TTP_XOR_MULT_DOSStub_bc43 {
  strings:
    $key_bc43 = { e8 2b [2] 9c 33 [2] db 31 [2] 9c 20 [2] d2 2c [2] de 26 [2] c9 2d [2] d2 63 [2] ef }

  condition:
    any of them
}