rule TTP_XOR_MULT_DOSStub_2b23 {
  strings:
    $key_2b23 = { 7f 4b [2] 0b 53 [2] 4c 51 [2] 0b 40 [2] 45 4c [2] 49 46 [2] 5e 4d [2] 45 03 [2] 78 }

  condition:
    any of them
}