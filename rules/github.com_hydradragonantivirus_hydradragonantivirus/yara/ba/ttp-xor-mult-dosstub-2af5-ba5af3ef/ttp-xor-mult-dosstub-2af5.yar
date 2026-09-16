rule TTP_XOR_MULT_DOSStub_2af5 {
  strings:
    $key_2af5 = { 7e 9d [2] 0a 85 [2] 4d 87 [2] 0a 96 [2] 44 9a [2] 48 90 [2] 5f 9b [2] 44 d5 [2] 79 }

  condition:
    any of them
}