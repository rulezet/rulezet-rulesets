rule TTP_XOR_MULT_DOSStub_eff8 {
  strings:
    $key_eff8 = { bb 90 [2] cf 88 [2] 88 8a [2] cf 9b [2] 81 97 [2] 8d 9d [2] 9a 96 [2] 81 d8 [2] bc }

  condition:
    any of them
}