rule TTP_XOR_MULT_DOSStub_6832 {
  strings:
    $key_6832 = { 3c 5a [2] 48 42 [2] 0f 40 [2] 48 51 [2] 06 5d [2] 0a 57 [2] 1d 5c [2] 06 12 [2] 3b }

  condition:
    any of them
}