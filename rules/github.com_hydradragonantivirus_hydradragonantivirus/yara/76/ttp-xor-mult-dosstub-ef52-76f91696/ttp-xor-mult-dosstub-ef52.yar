rule TTP_XOR_MULT_DOSStub_ef52 {
  strings:
    $key_ef52 = { bb 3a [2] cf 22 [2] 88 20 [2] cf 31 [2] 81 3d [2] 8d 37 [2] 9a 3c [2] 81 72 [2] bc }

  condition:
    any of them
}