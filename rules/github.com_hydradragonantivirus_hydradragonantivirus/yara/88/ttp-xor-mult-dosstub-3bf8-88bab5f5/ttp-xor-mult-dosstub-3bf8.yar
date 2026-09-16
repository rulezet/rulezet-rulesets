rule TTP_XOR_MULT_DOSStub_3bf8 {
  strings:
    $key_3bf8 = { 6f 90 [2] 1b 88 [2] 5c 8a [2] 1b 9b [2] 55 97 [2] 59 9d [2] 4e 96 [2] 55 d8 [2] 68 }

  condition:
    any of them
}