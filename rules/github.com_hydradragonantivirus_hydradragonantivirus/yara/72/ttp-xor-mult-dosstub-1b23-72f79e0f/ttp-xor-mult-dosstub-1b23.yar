rule TTP_XOR_MULT_DOSStub_1b23 {
  strings:
    $key_1b23 = { 4f 4b [2] 3b 53 [2] 7c 51 [2] 3b 40 [2] 75 4c [2] 79 46 [2] 6e 4d [2] 75 03 [2] 48 }

  condition:
    any of them
}