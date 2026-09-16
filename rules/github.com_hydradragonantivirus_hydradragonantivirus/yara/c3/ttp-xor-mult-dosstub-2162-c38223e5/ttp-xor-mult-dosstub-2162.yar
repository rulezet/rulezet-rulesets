rule TTP_XOR_MULT_DOSStub_2162 {
  strings:
    $key_2162 = { 75 0a [2] 01 12 [2] 46 10 [2] 01 01 [2] 4f 0d [2] 43 07 [2] 54 0c [2] 4f 42 [2] 72 }

  condition:
    any of them
}