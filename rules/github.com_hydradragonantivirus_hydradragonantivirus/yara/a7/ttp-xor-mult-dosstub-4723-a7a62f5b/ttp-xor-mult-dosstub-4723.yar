rule TTP_XOR_MULT_DOSStub_4723 {
  strings:
    $key_4723 = { 13 4b [2] 67 53 [2] 20 51 [2] 67 40 [2] 29 4c [2] 25 46 [2] 32 4d [2] 29 03 [2] 14 }

  condition:
    any of them
}