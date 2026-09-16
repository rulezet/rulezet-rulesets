rule TTP_XOR_MULT_DOSStub_6a34 {
  strings:
    $key_6a34 = { 3e 5c [2] 4a 44 [2] 0d 46 [2] 4a 57 [2] 04 5b [2] 08 51 [2] 1f 5a [2] 04 14 [2] 39 }

  condition:
    any of them
}