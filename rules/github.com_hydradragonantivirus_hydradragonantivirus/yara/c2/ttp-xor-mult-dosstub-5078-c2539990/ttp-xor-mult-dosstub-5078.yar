rule TTP_XOR_MULT_DOSStub_5078 {
  strings:
    $key_5078 = { 04 10 [2] 70 08 [2] 37 0a [2] 70 1b [2] 3e 17 [2] 32 1d [2] 25 16 [2] 3e 58 [2] 03 }

  condition:
    any of them
}