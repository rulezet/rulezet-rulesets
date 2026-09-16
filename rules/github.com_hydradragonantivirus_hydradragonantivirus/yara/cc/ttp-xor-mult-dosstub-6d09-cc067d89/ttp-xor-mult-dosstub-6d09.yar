rule TTP_XOR_MULT_DOSStub_6d09 {
  strings:
    $key_6d09 = { 39 61 [2] 4d 79 [2] 0a 7b [2] 4d 6a [2] 03 66 [2] 0f 6c [2] 18 67 [2] 03 29 [2] 3e }

  condition:
    any of them
}