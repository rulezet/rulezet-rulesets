rule TTP_XOR_MULT_DOSStub_6d47 {
  strings:
    $key_6d47 = { 39 2f [2] 4d 37 [2] 0a 35 [2] 4d 24 [2] 03 28 [2] 0f 22 [2] 18 29 [2] 03 67 [2] 3e }

  condition:
    any of them
}