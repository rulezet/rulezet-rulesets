rule TTP_XOR_MULT_DOSStub_2a35 {
  strings:
    $key_2a35 = { 7e 5d [2] 0a 45 [2] 4d 47 [2] 0a 56 [2] 44 5a [2] 48 50 [2] 5f 5b [2] 44 15 [2] 79 }

  condition:
    any of them
}