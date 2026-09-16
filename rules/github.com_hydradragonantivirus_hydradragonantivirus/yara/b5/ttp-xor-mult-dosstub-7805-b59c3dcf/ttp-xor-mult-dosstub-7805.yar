rule TTP_XOR_MULT_DOSStub_7805 {
  strings:
    $key_7805 = { 2c 6d [2] 58 75 [2] 1f 77 [2] 58 66 [2] 16 6a [2] 1a 60 [2] 0d 6b [2] 16 25 [2] 2b }

  condition:
    any of them
}