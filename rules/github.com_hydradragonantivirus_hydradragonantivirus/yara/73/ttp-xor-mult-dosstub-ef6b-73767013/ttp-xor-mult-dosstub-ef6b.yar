rule TTP_XOR_MULT_DOSStub_ef6b {
  strings:
    $key_ef6b = { bb 03 [2] cf 1b [2] 88 19 [2] cf 08 [2] 81 04 [2] 8d 0e [2] 9a 05 [2] 81 4b [2] bc }

  condition:
    any of them
}