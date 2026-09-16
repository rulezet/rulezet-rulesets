rule TTP_XOR_MULT_DOSStub_1828 {
  strings:
    $key_1828 = { 4c 40 [2] 38 58 [2] 7f 5a [2] 38 4b [2] 76 47 [2] 7a 4d [2] 6d 46 [2] 76 08 [2] 4b }

  condition:
    any of them
}