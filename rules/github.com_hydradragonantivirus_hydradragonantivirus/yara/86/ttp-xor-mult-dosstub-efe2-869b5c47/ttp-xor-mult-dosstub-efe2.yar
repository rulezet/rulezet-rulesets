rule TTP_XOR_MULT_DOSStub_efe2 {
  strings:
    $key_efe2 = { bb 8a [2] cf 92 [2] 88 90 [2] cf 81 [2] 81 8d [2] 8d 87 [2] 9a 8c [2] 81 c2 [2] bc }

  condition:
    any of them
}