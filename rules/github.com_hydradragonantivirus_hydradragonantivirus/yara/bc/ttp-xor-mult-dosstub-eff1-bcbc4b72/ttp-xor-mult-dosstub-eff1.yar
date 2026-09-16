rule TTP_XOR_MULT_DOSStub_eff1 {
  strings:
    $key_eff1 = { bb 99 [2] cf 81 [2] 88 83 [2] cf 92 [2] 81 9e [2] 8d 94 [2] 9a 9f [2] 81 d1 [2] bc }

  condition:
    any of them
}