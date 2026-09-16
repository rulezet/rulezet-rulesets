rule TTP_XOR_MULT_DOSStub_ef6c {
  strings:
    $key_ef6c = { bb 04 [2] cf 1c [2] 88 1e [2] cf 0f [2] 81 03 [2] 8d 09 [2] 9a 02 [2] 81 4c [2] bc }

  condition:
    any of them
}