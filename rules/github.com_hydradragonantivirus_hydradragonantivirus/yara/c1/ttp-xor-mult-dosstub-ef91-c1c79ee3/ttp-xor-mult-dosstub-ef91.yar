rule TTP_XOR_MULT_DOSStub_ef91 {
  strings:
    $key_ef91 = { bb f9 [2] cf e1 [2] 88 e3 [2] cf f2 [2] 81 fe [2] 8d f4 [2] 9a ff [2] 81 b1 [2] bc }

  condition:
    any of them
}