rule TTP_XOR_MULT_DOSStub_6b23 {
  strings:
    $key_6b23 = { 3f 4b [2] 4b 53 [2] 0c 51 [2] 4b 40 [2] 05 4c [2] 09 46 [2] 1e 4d [2] 05 03 [2] 38 }

  condition:
    any of them
}