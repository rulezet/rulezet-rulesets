rule TTP_XOR_MULT_DOSStub_4904 {
  strings:
    $key_4904 = { 1d 6c [2] 69 74 [2] 2e 76 [2] 69 67 [2] 27 6b [2] 2b 61 [2] 3c 6a [2] 27 24 [2] 1a }

  condition:
    any of them
}