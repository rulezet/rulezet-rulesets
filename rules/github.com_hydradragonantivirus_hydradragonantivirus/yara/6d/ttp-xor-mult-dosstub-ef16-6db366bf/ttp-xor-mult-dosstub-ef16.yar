rule TTP_XOR_MULT_DOSStub_ef16 {
  strings:
    $key_ef16 = { bb 7e [2] cf 66 [2] 88 64 [2] cf 75 [2] 81 79 [2] 8d 73 [2] 9a 78 [2] 81 36 [2] bc }

  condition:
    any of them
}