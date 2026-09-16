rule TTP_XOR_MULT_DOSStub_2a15 {
  strings:
    $key_2a15 = { 7e 7d [2] 0a 65 [2] 4d 67 [2] 0a 76 [2] 44 7a [2] 48 70 [2] 5f 7b [2] 44 35 [2] 79 }

  condition:
    any of them
}