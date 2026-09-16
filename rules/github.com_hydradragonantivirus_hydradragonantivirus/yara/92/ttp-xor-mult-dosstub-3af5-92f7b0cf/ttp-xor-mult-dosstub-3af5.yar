rule TTP_XOR_MULT_DOSStub_3af5 {
  strings:
    $key_3af5 = { 6e 9d [2] 1a 85 [2] 5d 87 [2] 1a 96 [2] 54 9a [2] 58 90 [2] 4f 9b [2] 54 d5 [2] 69 }

  condition:
    any of them
}