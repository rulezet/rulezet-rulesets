rule TTP_XOR_MULT_DOSStub_6d57 {
  strings:
    $key_6d57 = { 39 3f [2] 4d 27 [2] 0a 25 [2] 4d 34 [2] 03 38 [2] 0f 32 [2] 18 39 [2] 03 77 [2] 3e }

  condition:
    any of them
}