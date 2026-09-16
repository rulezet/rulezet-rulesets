rule TTP_XOR_MULT_DOSStub_1328 {
  strings:
    $key_1328 = { 47 40 [2] 33 58 [2] 74 5a [2] 33 4b [2] 7d 47 [2] 71 4d [2] 66 46 [2] 7d 08 [2] 40 }

  condition:
    any of them
}