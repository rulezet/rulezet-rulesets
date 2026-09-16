rule TTP_XOR_MULT_DOSStub_ef25 {
  strings:
    $key_ef25 = { bb 4d [2] cf 55 [2] 88 57 [2] cf 46 [2] 81 4a [2] 8d 40 [2] 9a 4b [2] 81 05 [2] bc }

  condition:
    any of them
}