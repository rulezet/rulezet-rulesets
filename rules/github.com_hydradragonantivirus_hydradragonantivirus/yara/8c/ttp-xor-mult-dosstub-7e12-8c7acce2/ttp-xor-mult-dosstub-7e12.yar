rule TTP_XOR_MULT_DOSStub_7e12 {
  strings:
    $key_7e12 = { 2a 7a [2] 5e 62 [2] 19 60 [2] 5e 71 [2] 10 7d [2] 1c 77 [2] 0b 7c [2] 10 32 [2] 2d }

  condition:
    any of them
}