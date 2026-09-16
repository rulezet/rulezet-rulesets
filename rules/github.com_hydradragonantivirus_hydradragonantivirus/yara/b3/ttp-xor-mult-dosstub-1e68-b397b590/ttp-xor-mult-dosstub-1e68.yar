rule TTP_XOR_MULT_DOSStub_1e68 {
  strings:
    $key_1e68 = { 4a 00 [2] 3e 18 [2] 79 1a [2] 3e 0b [2] 70 07 [2] 7c 0d [2] 6b 06 [2] 70 48 [2] 4d }

  condition:
    any of them
}