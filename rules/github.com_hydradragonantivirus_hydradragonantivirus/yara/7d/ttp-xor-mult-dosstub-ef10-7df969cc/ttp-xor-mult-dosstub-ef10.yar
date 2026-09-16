rule TTP_XOR_MULT_DOSStub_ef10 {
  strings:
    $key_ef10 = { bb 78 [2] cf 60 [2] 88 62 [2] cf 73 [2] 81 7f [2] 8d 75 [2] 9a 7e [2] 81 30 [2] bc }

  condition:
    any of them
}