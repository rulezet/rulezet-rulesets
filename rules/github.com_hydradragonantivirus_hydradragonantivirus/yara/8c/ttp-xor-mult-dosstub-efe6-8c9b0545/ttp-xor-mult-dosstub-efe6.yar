rule TTP_XOR_MULT_DOSStub_efe6 {
  strings:
    $key_efe6 = { bb 8e [2] cf 96 [2] 88 94 [2] cf 85 [2] 81 89 [2] 8d 83 [2] 9a 88 [2] 81 c6 [2] bc }

  condition:
    any of them
}