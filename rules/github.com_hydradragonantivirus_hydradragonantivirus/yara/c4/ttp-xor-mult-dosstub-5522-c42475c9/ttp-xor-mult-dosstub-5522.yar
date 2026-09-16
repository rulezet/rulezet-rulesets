rule TTP_XOR_MULT_DOSStub_5522 {
  strings:
    $key_5522 = { 01 4a [2] 75 52 [2] 32 50 [2] 75 41 [2] 3b 4d [2] 37 47 [2] 20 4c [2] 3b 02 [2] 06 }

  condition:
    any of them
}