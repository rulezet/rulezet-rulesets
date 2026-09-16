rule TTP_XOR_MULT_DOSStub_7904 {
  strings:
    $key_7904 = { 2d 6c [2] 59 74 [2] 1e 76 [2] 59 67 [2] 17 6b [2] 1b 61 [2] 0c 6a [2] 17 24 [2] 2a }

  condition:
    any of them
}