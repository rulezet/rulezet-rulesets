rule TTP_XOR_MULT_DOSStub_1bf8 {
  strings:
    $key_1bf8 = { 4f 90 [2] 3b 88 [2] 7c 8a [2] 3b 9b [2] 75 97 [2] 79 9d [2] 6e 96 [2] 75 d8 [2] 48 }

  condition:
    any of them
}