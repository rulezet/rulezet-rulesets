rule TTP_XOR_MULT_DOSStub_3b79 {
  strings:
    $key_3b79 = { 6f 11 [2] 1b 09 [2] 5c 0b [2] 1b 1a [2] 55 16 [2] 59 1c [2] 4e 17 [2] 55 59 [2] 68 }

  condition:
    any of them
}