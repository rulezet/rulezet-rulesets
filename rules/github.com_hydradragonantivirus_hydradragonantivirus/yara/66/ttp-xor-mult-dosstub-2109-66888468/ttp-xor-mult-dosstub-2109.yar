rule TTP_XOR_MULT_DOSStub_2109 {
  strings:
    $key_2109 = { 75 61 [2] 01 79 [2] 46 7b [2] 01 6a [2] 4f 66 [2] 43 6c [2] 54 67 [2] 4f 29 [2] 72 }

  condition:
    any of them
}