rule TTP_XOR_MULT_DOSStub_7e19 {
  strings:
    $key_7e19 = { 2a 71 [2] 5e 69 [2] 19 6b [2] 5e 7a [2] 10 76 [2] 1c 7c [2] 0b 77 [2] 10 39 [2] 2d }

  condition:
    any of them
}