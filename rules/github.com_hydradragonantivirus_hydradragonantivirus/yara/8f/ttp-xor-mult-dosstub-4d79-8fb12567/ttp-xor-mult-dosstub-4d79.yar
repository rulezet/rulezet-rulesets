rule TTP_XOR_MULT_DOSStub_4d79 {
  strings:
    $key_4d79 = { 19 11 [2] 6d 09 [2] 2a 0b [2] 6d 1a [2] 23 16 [2] 2f 1c [2] 38 17 [2] 23 59 [2] 1e }

  condition:
    any of them
}