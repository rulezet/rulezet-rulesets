rule TTP_XOR_MULT_DOSStub_3c64 {
  strings:
    $key_3c64 = { 68 0c [2] 1c 14 [2] 5b 16 [2] 1c 07 [2] 52 0b [2] 5e 01 [2] 49 0a [2] 52 44 [2] 6f }

  condition:
    any of them
}