rule TTP_XOR_MULT_DOSStub_7e35 {
  strings:
    $key_7e35 = { 2a 5d [2] 5e 45 [2] 19 47 [2] 5e 56 [2] 10 5a [2] 1c 50 [2] 0b 5b [2] 10 15 [2] 2d }

  condition:
    any of them
}