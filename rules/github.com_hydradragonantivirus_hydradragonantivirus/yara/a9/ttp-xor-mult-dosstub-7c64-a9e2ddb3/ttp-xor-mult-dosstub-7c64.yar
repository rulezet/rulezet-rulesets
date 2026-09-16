rule TTP_XOR_MULT_DOSStub_7c64 {
  strings:
    $key_7c64 = { 28 0c [2] 5c 14 [2] 1b 16 [2] 5c 07 [2] 12 0b [2] 1e 01 [2] 09 0a [2] 12 44 [2] 2f }

  condition:
    any of them
}