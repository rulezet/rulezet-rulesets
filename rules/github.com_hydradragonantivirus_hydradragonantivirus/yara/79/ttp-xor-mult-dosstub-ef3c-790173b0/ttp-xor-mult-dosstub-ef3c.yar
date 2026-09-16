rule TTP_XOR_MULT_DOSStub_ef3c {
  strings:
    $key_ef3c = { bb 54 [2] cf 4c [2] 88 4e [2] cf 5f [2] 81 53 [2] 8d 59 [2] 9a 52 [2] 81 1c [2] bc }

  condition:
    any of them
}