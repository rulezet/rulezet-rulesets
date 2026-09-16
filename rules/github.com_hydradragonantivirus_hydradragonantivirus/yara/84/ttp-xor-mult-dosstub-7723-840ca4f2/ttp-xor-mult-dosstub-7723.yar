rule TTP_XOR_MULT_DOSStub_7723 {
  strings:
    $key_7723 = { 23 4b [2] 57 53 [2] 10 51 [2] 57 40 [2] 19 4c [2] 15 46 [2] 02 4d [2] 19 03 [2] 24 }

  condition:
    any of them
}