rule TTP_XOR_MULT_DOSStub_ef2a {
  strings:
    $key_ef2a = { bb 42 [2] cf 5a [2] 88 58 [2] cf 49 [2] 81 45 [2] 8d 4f [2] 9a 44 [2] 81 0a [2] bc }

  condition:
    any of them
}