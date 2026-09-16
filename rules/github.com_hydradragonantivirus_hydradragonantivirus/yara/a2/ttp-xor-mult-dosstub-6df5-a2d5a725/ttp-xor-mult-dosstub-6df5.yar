rule TTP_XOR_MULT_DOSStub_6df5 {
  strings:
    $key_6df5 = { 39 9d [2] 4d 85 [2] 0a 87 [2] 4d 96 [2] 03 9a [2] 0f 90 [2] 18 9b [2] 03 d5 [2] 3e }

  condition:
    any of them
}