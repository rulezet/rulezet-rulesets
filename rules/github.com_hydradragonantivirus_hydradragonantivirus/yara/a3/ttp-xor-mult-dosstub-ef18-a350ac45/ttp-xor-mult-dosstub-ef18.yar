rule TTP_XOR_MULT_DOSStub_ef18 {
  strings:
    $key_ef18 = { bb 70 [2] cf 68 [2] 88 6a [2] cf 7b [2] 81 77 [2] 8d 7d [2] 9a 76 [2] 81 38 [2] bc }

  condition:
    any of them
}