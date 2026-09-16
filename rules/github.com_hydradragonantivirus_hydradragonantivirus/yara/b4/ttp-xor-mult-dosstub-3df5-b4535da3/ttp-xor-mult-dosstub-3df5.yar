rule TTP_XOR_MULT_DOSStub_3df5 {
  strings:
    $key_3df5 = { 69 9d [2] 1d 85 [2] 5a 87 [2] 1d 96 [2] 53 9a [2] 5f 90 [2] 48 9b [2] 53 d5 [2] 6e }

  condition:
    any of them
}