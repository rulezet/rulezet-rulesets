rule TTP_XOR_MULT_DOSStub_3c79 {
  strings:
    $key_3c79 = { 68 11 [2] 1c 09 [2] 5b 0b [2] 1c 1a [2] 52 16 [2] 5e 1c [2] 49 17 [2] 52 59 [2] 6f }

  condition:
    any of them
}