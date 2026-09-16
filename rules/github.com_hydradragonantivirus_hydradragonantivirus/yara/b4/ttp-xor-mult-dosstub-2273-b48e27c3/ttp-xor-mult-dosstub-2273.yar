rule TTP_XOR_MULT_DOSStub_2273 {
  strings:
    $key_2273 = { 76 1b [2] 02 03 [2] 45 01 [2] 02 10 [2] 4c 1c [2] 40 16 [2] 57 1d [2] 4c 53 [2] 71 }

  condition:
    any of them
}