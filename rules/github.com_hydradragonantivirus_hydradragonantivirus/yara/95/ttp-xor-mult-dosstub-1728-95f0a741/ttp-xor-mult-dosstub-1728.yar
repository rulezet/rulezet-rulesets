rule TTP_XOR_MULT_DOSStub_1728 {
  strings:
    $key_1728 = { 43 40 [2] 37 58 [2] 70 5a [2] 37 4b [2] 79 47 [2] 75 4d [2] 62 46 [2] 79 08 [2] 44 }

  condition:
    any of them
}