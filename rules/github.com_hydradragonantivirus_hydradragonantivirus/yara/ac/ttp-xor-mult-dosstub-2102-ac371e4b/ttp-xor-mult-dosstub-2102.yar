rule TTP_XOR_MULT_DOSStub_2102 {
  strings:
    $key_2102 = { 75 6a [2] 01 72 [2] 46 70 [2] 01 61 [2] 4f 6d [2] 43 67 [2] 54 6c [2] 4f 22 [2] 72 }

  condition:
    any of them
}