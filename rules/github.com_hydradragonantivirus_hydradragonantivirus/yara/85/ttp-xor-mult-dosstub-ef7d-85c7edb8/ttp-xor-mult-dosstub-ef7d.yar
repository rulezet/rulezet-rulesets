rule TTP_XOR_MULT_DOSStub_ef7d {
  strings:
    $key_ef7d = { bb 15 [2] cf 0d [2] 88 0f [2] cf 1e [2] 81 12 [2] 8d 18 [2] 9a 13 [2] 81 5d [2] bc }

  condition:
    any of them
}