rule TTP_XOR_MULT_DOSStub_ef71 {
  strings:
    $key_ef71 = { bb 19 [2] cf 01 [2] 88 03 [2] cf 12 [2] 81 1e [2] 8d 14 [2] 9a 1f [2] 81 51 [2] bc }

  condition:
    any of them
}