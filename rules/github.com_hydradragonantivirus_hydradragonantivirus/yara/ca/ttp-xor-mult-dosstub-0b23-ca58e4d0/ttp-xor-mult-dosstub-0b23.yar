rule TTP_XOR_MULT_DOSStub_0b23 {
  strings:
    $key_0b23 = { 5f 4b [2] 2b 53 [2] 6c 51 [2] 2b 40 [2] 65 4c [2] 69 46 [2] 7e 4d [2] 65 03 [2] 58 }

  condition:
    any of them
}