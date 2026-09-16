rule TTP_XOR_MULT_DOSStub_6871 {
  strings:
    $key_6871 = { 3c 19 [2] 48 01 [2] 0f 03 [2] 48 12 [2] 06 1e [2] 0a 14 [2] 1d 1f [2] 06 51 [2] 3b }

  condition:
    any of them
}