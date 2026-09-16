rule TTP_XOR_MULT_DOSStub_6d59 {
  strings:
    $key_6d59 = { 39 31 [2] 4d 29 [2] 0a 2b [2] 4d 3a [2] 03 36 [2] 0f 3c [2] 18 37 [2] 03 79 [2] 3e }

  condition:
    any of them
}