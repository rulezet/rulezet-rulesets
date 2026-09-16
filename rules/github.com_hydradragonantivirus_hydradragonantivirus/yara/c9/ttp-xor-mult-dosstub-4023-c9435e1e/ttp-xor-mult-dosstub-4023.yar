rule TTP_XOR_MULT_DOSStub_4023 {
  strings:
    $key_4023 = { 14 4b [2] 60 53 [2] 27 51 [2] 60 40 [2] 2e 4c [2] 22 46 [2] 35 4d [2] 2e 03 [2] 13 }

  condition:
    any of them
}