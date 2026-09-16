rule TTP_XOR_MULT_DOSStub_ef2c {
  strings:
    $key_ef2c = { bb 44 [2] cf 5c [2] 88 5e [2] cf 4f [2] 81 43 [2] 8d 49 [2] 9a 42 [2] 81 0c [2] bc }

  condition:
    any of them
}