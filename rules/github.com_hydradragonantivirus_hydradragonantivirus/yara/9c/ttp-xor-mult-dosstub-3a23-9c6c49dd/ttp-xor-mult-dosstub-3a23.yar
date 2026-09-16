rule TTP_XOR_MULT_DOSStub_3a23 {
  strings:
    $key_3a23 = { 6e 4b [2] 1a 53 [2] 5d 51 [2] 1a 40 [2] 54 4c [2] 58 46 [2] 4f 4d [2] 54 03 [2] 69 }

  condition:
    any of them
}