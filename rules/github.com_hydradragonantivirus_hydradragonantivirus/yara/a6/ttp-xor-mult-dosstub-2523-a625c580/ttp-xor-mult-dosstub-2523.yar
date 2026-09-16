rule TTP_XOR_MULT_DOSStub_2523 {
  strings:
    $key_2523 = { 71 4b [2] 05 53 [2] 42 51 [2] 05 40 [2] 4b 4c [2] 47 46 [2] 50 4d [2] 4b 03 [2] 76 }

  condition:
    any of them
}