rule TTP_XOR_MULT_DOSStub_6b54 {
  strings:
    $key_6b54 = { 3f 3c [2] 4b 24 [2] 0c 26 [2] 4b 37 [2] 05 3b [2] 09 31 [2] 1e 3a [2] 05 74 [2] 38 }

  condition:
    any of them
}