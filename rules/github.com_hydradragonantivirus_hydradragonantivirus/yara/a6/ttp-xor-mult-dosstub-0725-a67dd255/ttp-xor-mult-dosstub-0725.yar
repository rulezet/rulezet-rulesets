rule TTP_XOR_MULT_DOSStub_0725 {
  strings:
    $key_0725 = { 53 4d [2] 27 55 [2] 60 57 [2] 27 46 [2] 69 4a [2] 65 40 [2] 72 4b [2] 69 05 [2] 54 }

  condition:
    any of them
}