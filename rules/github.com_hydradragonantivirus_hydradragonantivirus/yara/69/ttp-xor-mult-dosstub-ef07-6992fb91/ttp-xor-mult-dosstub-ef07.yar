rule TTP_XOR_MULT_DOSStub_ef07 {
  strings:
    $key_ef07 = { bb 6f [2] cf 77 [2] 88 75 [2] cf 64 [2] 81 68 [2] 8d 62 [2] 9a 69 [2] 81 27 [2] bc }

  condition:
    any of them
}