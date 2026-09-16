rule TTP_XOR_MULT_DOSStub_7e05 {
  strings:
    $key_7e05 = { 2a 6d [2] 5e 75 [2] 19 77 [2] 5e 66 [2] 10 6a [2] 1c 60 [2] 0b 6b [2] 10 25 [2] 2d }

  condition:
    any of them
}