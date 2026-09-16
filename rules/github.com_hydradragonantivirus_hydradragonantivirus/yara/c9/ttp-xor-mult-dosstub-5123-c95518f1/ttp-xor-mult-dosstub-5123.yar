rule TTP_XOR_MULT_DOSStub_5123 {
  strings:
    $key_5123 = { 05 4b [2] 71 53 [2] 36 51 [2] 71 40 [2] 3f 4c [2] 33 46 [2] 24 4d [2] 3f 03 [2] 02 }

  condition:
    any of them
}