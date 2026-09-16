rule TTP_XOR_MULT_DOSStub_eff2 {
  strings:
    $key_eff2 = { bb 9a [2] cf 82 [2] 88 80 [2] cf 91 [2] 81 9d [2] 8d 97 [2] 9a 9c [2] 81 d2 [2] bc }

  condition:
    any of them
}