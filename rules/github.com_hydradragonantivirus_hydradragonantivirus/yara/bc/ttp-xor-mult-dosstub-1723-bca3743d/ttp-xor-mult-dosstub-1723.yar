rule TTP_XOR_MULT_DOSStub_1723 {
  strings:
    $key_1723 = { 43 4b [2] 37 53 [2] 70 51 [2] 37 40 [2] 79 4c [2] 75 46 [2] 62 4d [2] 79 03 [2] 44 }

  condition:
    any of them
}