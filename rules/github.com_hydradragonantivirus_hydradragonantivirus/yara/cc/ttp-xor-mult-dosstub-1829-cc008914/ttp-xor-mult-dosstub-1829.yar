rule TTP_XOR_MULT_DOSStub_1829 {
  strings:
    $key_1829 = { 4c 41 [2] 38 59 [2] 7f 5b [2] 38 4a [2] 76 46 [2] 7a 4c [2] 6d 47 [2] 76 09 [2] 4b }

  condition:
    any of them
}