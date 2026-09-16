rule TTP_XOR_MULT_DOSStub_ef55 {
  strings:
    $key_ef55 = { bb 3d [2] cf 25 [2] 88 27 [2] cf 36 [2] 81 3a [2] 8d 30 [2] 9a 3b [2] 81 75 [2] bc }

  condition:
    any of them
}