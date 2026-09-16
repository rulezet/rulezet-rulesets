rule TTP_XOR_MULT_DOSStub_ef64 {
  strings:
    $key_ef64 = { bb 0c [2] cf 14 [2] 88 16 [2] cf 07 [2] 81 0b [2] 8d 01 [2] 9a 0a [2] 81 44 [2] bc }

  condition:
    any of them
}