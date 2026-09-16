rule TTP_XOR_MULT_DOSStub_efa9 {
  strings:
    $key_efa9 = { bb c1 [2] cf d9 [2] 88 db [2] cf ca [2] 81 c6 [2] 8d cc [2] 9a c7 [2] 81 89 [2] bc }

  condition:
    any of them
}