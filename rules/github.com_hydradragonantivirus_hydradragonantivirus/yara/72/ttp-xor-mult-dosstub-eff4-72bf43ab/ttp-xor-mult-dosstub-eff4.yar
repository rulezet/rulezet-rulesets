rule TTP_XOR_MULT_DOSStub_eff4 {
  strings:
    $key_eff4 = { bb 9c [2] cf 84 [2] 88 86 [2] cf 97 [2] 81 9b [2] 8d 91 [2] 9a 9a [2] 81 d4 [2] bc }

  condition:
    any of them
}