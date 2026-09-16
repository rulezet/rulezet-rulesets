rule TTP_XOR_MULT_DOSStub_1ef5 {
  strings:
    $key_1ef5 = { 4a 9d [2] 3e 85 [2] 79 87 [2] 3e 96 [2] 70 9a [2] 7c 90 [2] 6b 9b [2] 70 d5 [2] 4d }

  condition:
    any of them
}