rule TTP_XOR_MULT_DOSStub_4b23 {
  strings:
    $key_4b23 = { 1f 4b [2] 6b 53 [2] 2c 51 [2] 6b 40 [2] 25 4c [2] 29 46 [2] 3e 4d [2] 25 03 [2] 18 }

  condition:
    any of them
}