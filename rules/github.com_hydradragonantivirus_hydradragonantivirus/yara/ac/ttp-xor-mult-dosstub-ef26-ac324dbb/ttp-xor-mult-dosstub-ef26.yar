rule TTP_XOR_MULT_DOSStub_ef26 {
  strings:
    $key_ef26 = { bb 4e [2] cf 56 [2] 88 54 [2] cf 45 [2] 81 49 [2] 8d 43 [2] 9a 48 [2] 81 06 [2] bc }

  condition:
    any of them
}