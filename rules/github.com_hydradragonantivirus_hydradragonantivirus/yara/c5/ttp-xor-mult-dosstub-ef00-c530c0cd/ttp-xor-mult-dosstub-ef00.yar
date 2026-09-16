rule TTP_XOR_MULT_DOSStub_ef00 {
  strings:
    $key_ef00 = { bb 68 [2] cf 70 [2] 88 72 [2] cf 63 [2] 81 6f [2] 8d 65 [2] 9a 6e [2] 81 20 [2] bc }

  condition:
    any of them
}