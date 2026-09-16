rule TTP_XOR_MULT_DOSStub_ef79 {
  strings:
    $key_ef79 = { bb 11 [2] cf 09 [2] 88 0b [2] cf 1a [2] 81 16 [2] 8d 1c [2] 9a 17 [2] 81 59 [2] bc }

  condition:
    any of them
}