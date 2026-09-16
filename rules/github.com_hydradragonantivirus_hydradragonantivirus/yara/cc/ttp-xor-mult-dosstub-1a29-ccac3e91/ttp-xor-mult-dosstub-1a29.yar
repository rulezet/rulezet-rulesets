rule TTP_XOR_MULT_DOSStub_1a29 {
  strings:
    $key_1a29 = { 4e 41 [2] 3a 59 [2] 7d 5b [2] 3a 4a [2] 74 46 [2] 78 4c [2] 6f 47 [2] 74 09 [2] 49 }

  condition:
    any of them
}