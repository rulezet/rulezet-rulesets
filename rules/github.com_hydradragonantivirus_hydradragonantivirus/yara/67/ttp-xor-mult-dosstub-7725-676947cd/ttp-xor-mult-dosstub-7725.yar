rule TTP_XOR_MULT_DOSStub_7725 {
  strings:
    $key_7725 = { 23 4d [2] 57 55 [2] 10 57 [2] 57 46 [2] 19 4a [2] 15 40 [2] 02 4b [2] 19 05 [2] 24 }

  condition:
    any of them
}