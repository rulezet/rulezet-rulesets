rule TTP_XOR_MULT_DOSStub_1a05 {
  strings:
    $key_1a05 = { 4e 6d [2] 3a 75 [2] 7d 77 [2] 3a 66 [2] 74 6a [2] 78 60 [2] 6f 6b [2] 74 25 [2] 49 }

  condition:
    any of them
}