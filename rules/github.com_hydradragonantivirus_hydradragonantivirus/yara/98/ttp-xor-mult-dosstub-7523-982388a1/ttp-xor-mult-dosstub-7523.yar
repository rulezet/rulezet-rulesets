rule TTP_XOR_MULT_DOSStub_7523 {
  strings:
    $key_7523 = { 21 4b [2] 55 53 [2] 12 51 [2] 55 40 [2] 1b 4c [2] 17 46 [2] 00 4d [2] 1b 03 [2] 26 }

  condition:
    any of them
}