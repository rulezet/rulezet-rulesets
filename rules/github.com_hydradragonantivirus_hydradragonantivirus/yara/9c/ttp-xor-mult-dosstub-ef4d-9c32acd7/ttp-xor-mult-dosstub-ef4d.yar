rule TTP_XOR_MULT_DOSStub_ef4d {
  strings:
    $key_ef4d = { bb 25 [2] cf 3d [2] 88 3f [2] cf 2e [2] 81 22 [2] 8d 28 [2] 9a 23 [2] 81 6d [2] bc }

  condition:
    any of them
}