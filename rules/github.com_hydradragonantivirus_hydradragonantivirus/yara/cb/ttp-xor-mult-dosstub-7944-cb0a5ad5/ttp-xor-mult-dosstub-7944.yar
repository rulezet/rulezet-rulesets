rule TTP_XOR_MULT_DOSStub_7944 {
  strings:
    $key_7944 = { 2d 2c [2] 59 34 [2] 1e 36 [2] 59 27 [2] 17 2b [2] 1b 21 [2] 0c 2a [2] 17 64 [2] 2a }

  condition:
    any of them
}