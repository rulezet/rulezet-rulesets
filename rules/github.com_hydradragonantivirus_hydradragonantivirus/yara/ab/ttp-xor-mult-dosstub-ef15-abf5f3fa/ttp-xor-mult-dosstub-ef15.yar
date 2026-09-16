rule TTP_XOR_MULT_DOSStub_ef15 {
  strings:
    $key_ef15 = { bb 7d [2] cf 65 [2] 88 67 [2] cf 76 [2] 81 7a [2] 8d 70 [2] 9a 7b [2] 81 35 [2] bc }

  condition:
    any of them
}