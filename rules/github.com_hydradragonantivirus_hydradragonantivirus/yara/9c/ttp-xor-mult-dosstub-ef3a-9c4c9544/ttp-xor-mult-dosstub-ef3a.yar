rule TTP_XOR_MULT_DOSStub_ef3a {
  strings:
    $key_ef3a = { bb 52 [2] cf 4a [2] 88 48 [2] cf 59 [2] 81 55 [2] 8d 5f [2] 9a 54 [2] 81 1a [2] bc }

  condition:
    any of them
}