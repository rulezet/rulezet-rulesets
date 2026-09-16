rule TTP_XOR_MULT_DOSStub_1e79 {
  strings:
    $key_1e79 = { 4a 11 [2] 3e 09 [2] 79 0b [2] 3e 1a [2] 70 16 [2] 7c 1c [2] 6b 17 [2] 70 59 [2] 4d }

  condition:
    any of them
}