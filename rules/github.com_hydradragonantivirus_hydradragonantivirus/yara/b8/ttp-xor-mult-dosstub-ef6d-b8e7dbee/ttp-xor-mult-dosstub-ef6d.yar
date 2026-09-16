rule TTP_XOR_MULT_DOSStub_ef6d {
  strings:
    $key_ef6d = { bb 05 [2] cf 1d [2] 88 1f [2] cf 0e [2] 81 02 [2] 8d 08 [2] 9a 03 [2] 81 4d [2] bc }

  condition:
    any of them
}