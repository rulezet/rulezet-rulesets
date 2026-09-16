rule TTP_XOR_MULT_DOSStub_ef0d {
  strings:
    $key_ef0d = { bb 65 [2] cf 7d [2] 88 7f [2] cf 6e [2] 81 62 [2] 8d 68 [2] 9a 63 [2] 81 2d [2] bc }

  condition:
    any of them
}