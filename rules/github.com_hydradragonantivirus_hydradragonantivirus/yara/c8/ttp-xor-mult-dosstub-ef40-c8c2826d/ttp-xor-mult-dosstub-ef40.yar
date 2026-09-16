rule TTP_XOR_MULT_DOSStub_ef40 {
  strings:
    $key_ef40 = { bb 28 [2] cf 30 [2] 88 32 [2] cf 23 [2] 81 2f [2] 8d 25 [2] 9a 2e [2] 81 60 [2] bc }

  condition:
    any of them
}