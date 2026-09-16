rule TTP_XOR_MULT_DOSStub_ef37 {
  strings:
    $key_ef37 = { bb 5f [2] cf 47 [2] 88 45 [2] cf 54 [2] 81 58 [2] 8d 52 [2] 9a 59 [2] 81 17 [2] bc }

  condition:
    any of them
}