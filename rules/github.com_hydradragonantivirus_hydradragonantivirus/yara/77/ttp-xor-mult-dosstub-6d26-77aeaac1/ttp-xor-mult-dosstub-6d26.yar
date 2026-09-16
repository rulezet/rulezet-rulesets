rule TTP_XOR_MULT_DOSStub_6d26 {
  strings:
    $key_6d26 = { 39 4e [2] 4d 56 [2] 0a 54 [2] 4d 45 [2] 03 49 [2] 0f 43 [2] 18 48 [2] 03 06 [2] 3e }

  condition:
    any of them
}