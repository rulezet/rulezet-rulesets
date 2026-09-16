rule TTP_XOR_MULT_DOSStub_5278 {
  strings:
    $key_5278 = { 06 10 [2] 72 08 [2] 35 0a [2] 72 1b [2] 3c 17 [2] 30 1d [2] 27 16 [2] 3c 58 [2] 01 }

  condition:
    any of them
}