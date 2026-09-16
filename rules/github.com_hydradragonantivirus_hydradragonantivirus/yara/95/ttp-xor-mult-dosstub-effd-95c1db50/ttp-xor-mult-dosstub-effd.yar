rule TTP_XOR_MULT_DOSStub_effd {
  strings:
    $key_effd = { bb 95 [2] cf 8d [2] 88 8f [2] cf 9e [2] 81 92 [2] 8d 98 [2] 9a 93 [2] 81 dd [2] bc }

  condition:
    any of them
}