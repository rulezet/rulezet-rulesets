rule TTP_XOR_MULT_DOSStub_4028 {
  strings:
    $key_4028 = { 14 40 [2] 60 58 [2] 27 5a [2] 60 4b [2] 2e 47 [2] 22 4d [2] 35 46 [2] 2e 08 [2] 13 }

  condition:
    any of them
}