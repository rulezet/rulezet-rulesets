rule TTP_XOR_MULT_DOSStub_4025 {
  strings:
    $key_4025 = { 14 4d [2] 60 55 [2] 27 57 [2] 60 46 [2] 2e 4a [2] 22 40 [2] 35 4b [2] 2e 05 [2] 13 }

  condition:
    any of them
}