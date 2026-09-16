rule TTP_XOR_MULT_DOSStub_6b34 {
  strings:
    $key_6b34 = { 3f 5c [2] 4b 44 [2] 0c 46 [2] 4b 57 [2] 05 5b [2] 09 51 [2] 1e 5a [2] 05 14 [2] 38 }

  condition:
    any of them
}