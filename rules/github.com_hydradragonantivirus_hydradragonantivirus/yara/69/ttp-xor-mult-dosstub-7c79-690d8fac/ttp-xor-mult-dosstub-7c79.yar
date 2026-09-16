rule TTP_XOR_MULT_DOSStub_7c79 {
  strings:
    $key_7c79 = { 28 11 [2] 5c 09 [2] 1b 0b [2] 5c 1a [2] 12 16 [2] 1e 1c [2] 09 17 [2] 12 59 [2] 2f }

  condition:
    any of them
}