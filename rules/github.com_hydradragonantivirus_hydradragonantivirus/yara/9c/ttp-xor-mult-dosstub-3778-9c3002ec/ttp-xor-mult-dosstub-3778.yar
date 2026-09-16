rule TTP_XOR_MULT_DOSStub_3778 {
  strings:
    $key_3778 = { 63 10 [2] 17 08 [2] 50 0a [2] 17 1b [2] 59 17 [2] 55 1d [2] 42 16 [2] 59 58 [2] 64 }

  condition:
    any of them
}