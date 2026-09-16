rule TTP_XOR_MULT_DOSStub_ef05 {
  strings:
    $key_ef05 = { bb 6d [2] cf 75 [2] 88 77 [2] cf 66 [2] 81 6a [2] 8d 60 [2] 9a 6b [2] 81 25 [2] bc }

  condition:
    any of them
}