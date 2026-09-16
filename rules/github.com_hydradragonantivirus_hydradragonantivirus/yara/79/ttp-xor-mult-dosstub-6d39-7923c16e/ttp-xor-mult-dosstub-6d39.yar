rule TTP_XOR_MULT_DOSStub_6d39 {
  strings:
    $key_6d39 = { 39 51 [2] 4d 49 [2] 0a 4b [2] 4d 5a [2] 03 56 [2] 0f 5c [2] 18 57 [2] 03 19 [2] 3e }

  condition:
    any of them
}