rule TTP_XOR_MULT_DOSStub_2df5 {
  strings:
    $key_2df5 = { 79 9d [2] 0d 85 [2] 4a 87 [2] 0d 96 [2] 43 9a [2] 4f 90 [2] 58 9b [2] 43 d5 [2] 7e }

  condition:
    any of them
}