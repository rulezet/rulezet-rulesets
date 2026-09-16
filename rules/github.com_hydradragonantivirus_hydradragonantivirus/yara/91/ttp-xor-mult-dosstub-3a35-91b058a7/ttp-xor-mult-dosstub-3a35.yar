rule TTP_XOR_MULT_DOSStub_3a35 {
  strings:
    $key_3a35 = { 6e 5d [2] 1a 45 [2] 5d 47 [2] 1a 56 [2] 54 5a [2] 58 50 [2] 4f 5b [2] 54 15 [2] 69 }

  condition:
    any of them
}