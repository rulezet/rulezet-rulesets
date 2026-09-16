rule TTP_XOR_MULT_DOSStub_7974 {
  strings:
    $key_7974 = { 2d 1c [2] 59 04 [2] 1e 06 [2] 59 17 [2] 17 1b [2] 1b 11 [2] 0c 1a [2] 17 54 [2] 2a }

  condition:
    any of them
}