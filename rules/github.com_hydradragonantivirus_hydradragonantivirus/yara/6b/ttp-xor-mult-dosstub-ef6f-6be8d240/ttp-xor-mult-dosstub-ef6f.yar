rule TTP_XOR_MULT_DOSStub_ef6f {
  strings:
    $key_ef6f = { bb 07 [2] cf 1f [2] 88 1d [2] cf 0c [2] 81 00 [2] 8d 0a [2] 9a 01 [2] 81 4f [2] bc }

  condition:
    any of them
}