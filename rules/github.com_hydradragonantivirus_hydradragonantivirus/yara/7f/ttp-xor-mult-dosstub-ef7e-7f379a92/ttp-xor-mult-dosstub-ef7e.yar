rule TTP_XOR_MULT_DOSStub_ef7e {
  strings:
    $key_ef7e = { bb 16 [2] cf 0e [2] 88 0c [2] cf 1d [2] 81 11 [2] 8d 1b [2] 9a 10 [2] 81 5e [2] bc }

  condition:
    any of them
}