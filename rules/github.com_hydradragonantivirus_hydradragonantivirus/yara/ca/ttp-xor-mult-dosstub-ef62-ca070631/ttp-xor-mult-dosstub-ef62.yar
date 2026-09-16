rule TTP_XOR_MULT_DOSStub_ef62 {
  strings:
    $key_ef62 = { bb 0a [2] cf 12 [2] 88 10 [2] cf 01 [2] 81 0d [2] 8d 07 [2] 9a 0c [2] 81 42 [2] bc }

  condition:
    any of them
}