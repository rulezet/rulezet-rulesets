rule TTP_XOR_MULT_DOSStub_6d18 {
  strings:
    $key_6d18 = { 39 70 [2] 4d 68 [2] 0a 6a [2] 4d 7b [2] 03 77 [2] 0f 7d [2] 18 76 [2] 03 38 [2] 3e }

  condition:
    any of them
}