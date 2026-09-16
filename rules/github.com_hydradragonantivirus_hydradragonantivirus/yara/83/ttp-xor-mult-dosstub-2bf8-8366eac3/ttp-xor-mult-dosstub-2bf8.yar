rule TTP_XOR_MULT_DOSStub_2bf8 {
  strings:
    $key_2bf8 = { 7f 90 [2] 0b 88 [2] 4c 8a [2] 0b 9b [2] 45 97 [2] 49 9d [2] 5e 96 [2] 45 d8 [2] 78 }

  condition:
    any of them
}