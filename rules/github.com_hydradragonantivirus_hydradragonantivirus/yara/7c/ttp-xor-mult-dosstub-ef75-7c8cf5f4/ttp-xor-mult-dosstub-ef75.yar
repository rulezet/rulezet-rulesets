rule TTP_XOR_MULT_DOSStub_ef75 {
  strings:
    $key_ef75 = { bb 1d [2] cf 05 [2] 88 07 [2] cf 16 [2] 81 1a [2] 8d 10 [2] 9a 1b [2] 81 55 [2] bc }

  condition:
    any of them
}