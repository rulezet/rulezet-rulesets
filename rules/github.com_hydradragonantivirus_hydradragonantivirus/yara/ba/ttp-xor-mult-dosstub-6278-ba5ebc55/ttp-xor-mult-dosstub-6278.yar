rule TTP_XOR_MULT_DOSStub_6278 {
  strings:
    $key_6278 = { 36 10 [2] 42 08 [2] 05 0a [2] 42 1b [2] 0c 17 [2] 00 1d [2] 17 16 [2] 0c 58 [2] 31 }

  condition:
    any of them
}