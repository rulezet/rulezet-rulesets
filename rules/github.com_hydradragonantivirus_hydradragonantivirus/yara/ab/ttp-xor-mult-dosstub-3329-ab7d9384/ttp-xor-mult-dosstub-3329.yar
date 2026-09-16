rule TTP_XOR_MULT_DOSStub_3329 {
  strings:
    $key_3329 = { 67 41 [2] 13 59 [2] 54 5b [2] 13 4a [2] 5d 46 [2] 51 4c [2] 46 47 [2] 5d 09 [2] 60 }

  condition:
    any of them
}