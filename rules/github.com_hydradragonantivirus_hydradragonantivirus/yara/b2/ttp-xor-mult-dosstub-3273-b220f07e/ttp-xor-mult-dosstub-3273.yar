rule TTP_XOR_MULT_DOSStub_3273 {
  strings:
    $key_3273 = { 66 1b [2] 12 03 [2] 55 01 [2] 12 10 [2] 5c 1c [2] 50 16 [2] 47 1d [2] 5c 53 [2] 61 }

  condition:
    any of them
}