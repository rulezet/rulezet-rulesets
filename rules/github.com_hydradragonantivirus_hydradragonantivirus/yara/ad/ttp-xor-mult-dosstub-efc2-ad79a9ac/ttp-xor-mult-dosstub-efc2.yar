rule TTP_XOR_MULT_DOSStub_efc2 {
  strings:
    $key_efc2 = { bb aa [2] cf b2 [2] 88 b0 [2] cf a1 [2] 81 ad [2] 8d a7 [2] 9a ac [2] 81 e2 [2] bc }

  condition:
    any of them
}