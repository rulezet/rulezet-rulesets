rule TTP_XOR_MULT_DOSStub_3125 {
  strings:
    $key_3125 = { 65 4d [2] 11 55 [2] 56 57 [2] 11 46 [2] 5f 4a [2] 53 40 [2] 44 4b [2] 5f 05 [2] 62 }

  condition:
    any of them
}