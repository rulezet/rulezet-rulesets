rule TTP_XOR_MULT_DOSStub_6d71 {
  strings:
    $key_6d71 = { 39 19 [2] 4d 01 [2] 0a 03 [2] 4d 12 [2] 03 1e [2] 0f 14 [2] 18 1f [2] 03 51 [2] 3e }

  condition:
    any of them
}