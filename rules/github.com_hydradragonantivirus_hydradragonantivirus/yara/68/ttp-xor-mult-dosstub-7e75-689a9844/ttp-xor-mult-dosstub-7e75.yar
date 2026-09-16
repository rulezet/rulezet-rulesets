rule TTP_XOR_MULT_DOSStub_7e75 {
  strings:
    $key_7e75 = { 2a 1d [2] 5e 05 [2] 19 07 [2] 5e 16 [2] 10 1a [2] 1c 10 [2] 0b 1b [2] 10 55 [2] 2d }

  condition:
    any of them
}