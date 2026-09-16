rule TTP_XOR_MULT_DOSStub_3308 {
  strings:
    $key_3308 = { 67 60 [2] 13 78 [2] 54 7a [2] 13 6b [2] 5d 67 [2] 51 6d [2] 46 66 [2] 5d 28 [2] 60 }

  condition:
    any of them
}