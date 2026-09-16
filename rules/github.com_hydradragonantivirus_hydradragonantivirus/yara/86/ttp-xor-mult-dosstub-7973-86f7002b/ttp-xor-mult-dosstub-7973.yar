rule TTP_XOR_MULT_DOSStub_7973 {
  strings:
    $key_7973 = { 2d 1b [2] 59 03 [2] 1e 01 [2] 59 10 [2] 17 1c [2] 1b 16 [2] 0c 1d [2] 17 53 [2] 2a }

  condition:
    any of them
}