rule TTP_XOR_MULT_DOSStub_6213 {
  strings:
    $key_6213 = { 36 7b [2] 42 63 [2] 05 61 [2] 42 70 [2] 0c 7c [2] 00 76 [2] 17 7d [2] 0c 33 [2] 31 }

  condition:
    any of them
}