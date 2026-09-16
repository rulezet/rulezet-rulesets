rule TTP_XOR_MULT_DOSStub_2a28 {
  strings:
    $key_2a28 = { 7e 40 [2] 0a 58 [2] 4d 5a [2] 0a 4b [2] 44 47 [2] 48 4d [2] 5f 46 [2] 44 08 [2] 79 }

  condition:
    any of them
}