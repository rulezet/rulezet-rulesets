rule TTP_XOR_MULT_DOSStub_3322 {
  strings:
    $key_3322 = { 67 4a [2] 13 52 [2] 54 50 [2] 13 41 [2] 5d 4d [2] 51 47 [2] 46 4c [2] 5d 02 [2] 60 }

  condition:
    any of them
}