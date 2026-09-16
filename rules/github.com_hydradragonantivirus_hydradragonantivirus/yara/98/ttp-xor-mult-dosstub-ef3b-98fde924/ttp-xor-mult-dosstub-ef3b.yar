rule TTP_XOR_MULT_DOSStub_ef3b {
  strings:
    $key_ef3b = { bb 53 [2] cf 4b [2] 88 49 [2] cf 58 [2] 81 54 [2] 8d 5e [2] 9a 55 [2] 81 1b [2] bc }

  condition:
    any of them
}