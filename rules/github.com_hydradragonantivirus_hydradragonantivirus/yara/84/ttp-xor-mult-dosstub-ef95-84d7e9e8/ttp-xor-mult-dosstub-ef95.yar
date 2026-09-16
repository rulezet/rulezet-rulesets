rule TTP_XOR_MULT_DOSStub_ef95 {
  strings:
    $key_ef95 = { bb fd [2] cf e5 [2] 88 e7 [2] cf f6 [2] 81 fa [2] 8d f0 [2] 9a fb [2] 81 b5 [2] bc }

  condition:
    any of them
}