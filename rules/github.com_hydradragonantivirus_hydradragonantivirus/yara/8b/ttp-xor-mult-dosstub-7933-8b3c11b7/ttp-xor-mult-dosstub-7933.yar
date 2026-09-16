rule TTP_XOR_MULT_DOSStub_7933 {
  strings:
    $key_7933 = { 2d 5b [2] 59 43 [2] 1e 41 [2] 59 50 [2] 17 5c [2] 1b 56 [2] 0c 5d [2] 17 13 [2] 2a }

  condition:
    any of them
}