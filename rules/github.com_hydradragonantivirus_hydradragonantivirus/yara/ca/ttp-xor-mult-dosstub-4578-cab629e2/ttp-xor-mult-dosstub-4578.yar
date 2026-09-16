rule TTP_XOR_MULT_DOSStub_4578 {
  strings:
    $key_4578 = { 11 10 [2] 65 08 [2] 22 0a [2] 65 1b [2] 2b 17 [2] 27 1d [2] 30 16 [2] 2b 58 [2] 16 }

  condition:
    any of them
}