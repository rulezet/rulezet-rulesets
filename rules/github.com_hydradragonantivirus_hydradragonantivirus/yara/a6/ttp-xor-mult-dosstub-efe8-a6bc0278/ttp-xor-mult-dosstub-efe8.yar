rule TTP_XOR_MULT_DOSStub_efe8 {
  strings:
    $key_efe8 = { bb 80 [2] cf 98 [2] 88 9a [2] cf 8b [2] 81 87 [2] 8d 8d [2] 9a 86 [2] 81 c8 [2] bc }

  condition:
    any of them
}