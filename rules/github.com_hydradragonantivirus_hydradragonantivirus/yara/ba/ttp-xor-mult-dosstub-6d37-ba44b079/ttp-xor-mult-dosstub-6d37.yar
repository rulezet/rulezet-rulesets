rule TTP_XOR_MULT_DOSStub_6d37 {
  strings:
    $key_6d37 = { 39 5f [2] 4d 47 [2] 0a 45 [2] 4d 54 [2] 03 58 [2] 0f 52 [2] 18 59 [2] 03 17 [2] 3e }

  condition:
    any of them
}