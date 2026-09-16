rule TTP_XOR_MULT_DOSStub_7e59 {
  strings:
    $key_7e59 = { 2a 31 [2] 5e 29 [2] 19 2b [2] 5e 3a [2] 10 36 [2] 1c 3c [2] 0b 37 [2] 10 79 [2] 2d }

  condition:
    any of them
}