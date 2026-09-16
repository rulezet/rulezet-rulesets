rule TTP_XOR_MULT_DOSStub_7b23 {
  strings:
    $key_7b23 = { 2f 4b [2] 5b 53 [2] 1c 51 [2] 5b 40 [2] 15 4c [2] 19 46 [2] 0e 4d [2] 15 03 [2] 28 }

  condition:
    any of them
}