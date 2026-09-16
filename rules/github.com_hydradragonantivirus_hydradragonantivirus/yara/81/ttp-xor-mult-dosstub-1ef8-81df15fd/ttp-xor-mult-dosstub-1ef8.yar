rule TTP_XOR_MULT_DOSStub_1ef8 {
  strings:
    $key_1ef8 = { 4a 90 [2] 3e 88 [2] 79 8a [2] 3e 9b [2] 70 97 [2] 7c 9d [2] 6b 96 [2] 70 d8 [2] 4d }

  condition:
    any of them
}