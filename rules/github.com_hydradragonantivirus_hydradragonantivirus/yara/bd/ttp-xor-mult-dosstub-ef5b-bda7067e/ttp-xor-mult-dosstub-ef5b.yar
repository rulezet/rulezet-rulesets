rule TTP_XOR_MULT_DOSStub_ef5b {
  strings:
    $key_ef5b = { bb 33 [2] cf 2b [2] 88 29 [2] cf 38 [2] 81 34 [2] 8d 3e [2] 9a 35 [2] 81 7b [2] bc }

  condition:
    any of them
}