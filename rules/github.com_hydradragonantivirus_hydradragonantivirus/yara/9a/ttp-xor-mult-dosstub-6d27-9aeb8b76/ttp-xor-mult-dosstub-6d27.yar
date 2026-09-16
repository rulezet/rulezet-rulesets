rule TTP_XOR_MULT_DOSStub_6d27 {
  strings:
    $key_6d27 = { 39 4f [2] 4d 57 [2] 0a 55 [2] 4d 44 [2] 03 48 [2] 0f 42 [2] 18 49 [2] 03 07 [2] 3e }

  condition:
    any of them
}