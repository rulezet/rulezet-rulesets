rule TTP_XOR_MULT_DOSStub_6d40 {
  strings:
    $key_6d40 = { 39 28 [2] 4d 30 [2] 0a 32 [2] 4d 23 [2] 03 2f [2] 0f 25 [2] 18 2e [2] 03 60 [2] 3e }

  condition:
    any of them
}