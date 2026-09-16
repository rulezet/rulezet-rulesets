rule TTP_XOR_MULT_DOSStub_4949 {
  strings:
    $key_4949 = { 1d 21 [2] 69 39 [2] 2e 3b [2] 69 2a [2] 27 26 [2] 2b 2c [2] 3c 27 [2] 27 69 [2] 1a }

  condition:
    any of them
}