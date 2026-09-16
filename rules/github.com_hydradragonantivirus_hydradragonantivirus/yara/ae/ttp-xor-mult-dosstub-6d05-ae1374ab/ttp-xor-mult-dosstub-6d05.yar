rule TTP_XOR_MULT_DOSStub_6d05 {
  strings:
    $key_6d05 = { 39 6d [2] 4d 75 [2] 0a 77 [2] 4d 66 [2] 03 6a [2] 0f 60 [2] 18 6b [2] 03 25 [2] 3e }

  condition:
    any of them
}