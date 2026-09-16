rule TTP_XOR_MULT_DOSStub_3328 {
  strings:
    $key_3328 = { 67 40 [2] 13 58 [2] 54 5a [2] 13 4b [2] 5d 47 [2] 51 4d [2] 46 46 [2] 5d 08 [2] 60 }

  condition:
    any of them
}