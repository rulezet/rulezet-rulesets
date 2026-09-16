rule TTP_XOR_MULT_DOSStub_6209 {
  strings:
    $key_6209 = { 36 61 [2] 42 79 [2] 05 7b [2] 42 6a [2] 0c 66 [2] 00 6c [2] 17 67 [2] 0c 29 [2] 31 }

  condition:
    any of them
}