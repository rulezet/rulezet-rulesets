rule TTP_XOR_MULT_DOSStub_7e48 {
  strings:
    $key_7e48 = { 2a 20 [2] 5e 38 [2] 19 3a [2] 5e 2b [2] 10 27 [2] 1c 2d [2] 0b 26 [2] 10 68 [2] 2d }

  condition:
    any of them
}