rule TTP_XOR_MULT_DOSStub_6473 {
  strings:
    $key_6473 = { 30 1b [2] 44 03 [2] 03 01 [2] 44 10 [2] 0a 1c [2] 06 16 [2] 11 1d [2] 0a 53 [2] 37 }

  condition:
    any of them
}