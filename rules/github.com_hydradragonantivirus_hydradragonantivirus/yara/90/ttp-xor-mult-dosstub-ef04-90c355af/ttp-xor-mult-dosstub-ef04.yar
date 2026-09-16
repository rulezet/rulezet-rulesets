rule TTP_XOR_MULT_DOSStub_ef04 {
  strings:
    $key_ef04 = { bb 6c [2] cf 74 [2] 88 76 [2] cf 67 [2] 81 6b [2] 8d 61 [2] 9a 6a [2] 81 24 [2] bc }

  condition:
    any of them
}