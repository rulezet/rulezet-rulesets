rule TTP_XOR_MULT_DOSStub_5222 {
  strings:
    $key_5222 = { 06 4a [2] 72 52 [2] 35 50 [2] 72 41 [2] 3c 4d [2] 30 47 [2] 27 4c [2] 3c 02 [2] 01 }

  condition:
    any of them
}