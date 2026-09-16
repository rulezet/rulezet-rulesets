rule TTP_XOR_MULT_DOSStub_3a29 {
  strings:
    $key_3a29 = { 6e 41 [2] 1a 59 [2] 5d 5b [2] 1a 4a [2] 54 46 [2] 58 4c [2] 4f 47 [2] 54 09 [2] 69 }

  condition:
    any of them
}