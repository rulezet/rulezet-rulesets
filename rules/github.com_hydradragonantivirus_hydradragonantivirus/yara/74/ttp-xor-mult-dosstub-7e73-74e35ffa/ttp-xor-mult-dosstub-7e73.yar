rule TTP_XOR_MULT_DOSStub_7e73 {
  strings:
    $key_7e73 = { 2a 1b [2] 5e 03 [2] 19 01 [2] 5e 10 [2] 10 1c [2] 1c 16 [2] 0b 1d [2] 10 53 [2] 2d }

  condition:
    any of them
}