rule TTP_XOR_MULT_DOSStub_6df8 {
  strings:
    $key_6df8 = { 39 90 [2] 4d 88 [2] 0a 8a [2] 4d 9b [2] 03 97 [2] 0f 9d [2] 18 96 [2] 03 d8 [2] 3e }

  condition:
    any of them
}