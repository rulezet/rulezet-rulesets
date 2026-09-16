rule TTP_XOR_MULT_DOSStub_1825 {
  strings:
    $key_1825 = { 4c 4d [2] 38 55 [2] 7f 57 [2] 38 46 [2] 76 4a [2] 7a 40 [2] 6d 4b [2] 76 05 [2] 4b }

  condition:
    any of them
}