rule TTP_XOR_MULT_DOSStub_5578 {
  strings:
    $key_5578 = { 01 10 [2] 75 08 [2] 32 0a [2] 75 1b [2] 3b 17 [2] 37 1d [2] 20 16 [2] 3b 58 [2] 06 }

  condition:
    any of them
}