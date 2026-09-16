rule TTP_XOR_MULT_DOSStub_ef36 {
  strings:
    $key_ef36 = { bb 5e [2] cf 46 [2] 88 44 [2] cf 55 [2] 81 59 [2] 8d 53 [2] 9a 58 [2] 81 16 [2] bc }

  condition:
    any of them
}