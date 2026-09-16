rule TTP_XOR_MULT_DOSStub_5423 {
  strings:
    $key_5423 = { 00 4b [2] 74 53 [2] 33 51 [2] 74 40 [2] 3a 4c [2] 36 46 [2] 21 4d [2] 3a 03 [2] 07 }

  condition:
    any of them
}