rule TTP_XOR_MULT_DOSStub_4022 {
  strings:
    $key_4022 = { 14 4a [2] 60 52 [2] 27 50 [2] 60 41 [2] 2e 4d [2] 22 47 [2] 35 4c [2] 2e 02 [2] 13 }

  condition:
    any of them
}