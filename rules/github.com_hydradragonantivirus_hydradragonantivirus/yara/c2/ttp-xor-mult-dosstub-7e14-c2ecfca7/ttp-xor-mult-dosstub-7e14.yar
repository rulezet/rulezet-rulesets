rule TTP_XOR_MULT_DOSStub_7e14 {
  strings:
    $key_7e14 = { 2a 7c [2] 5e 64 [2] 19 66 [2] 5e 77 [2] 10 7b [2] 1c 71 [2] 0b 7a [2] 10 34 [2] 2d }

  condition:
    any of them
}