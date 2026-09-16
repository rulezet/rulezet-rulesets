rule TTP_XOR_MULT_DOSStub_ef65 {
  strings:
    $key_ef65 = { bb 0d [2] cf 15 [2] 88 17 [2] cf 06 [2] 81 0a [2] 8d 00 [2] 9a 0b [2] 81 45 [2] bc }

  condition:
    any of them
}