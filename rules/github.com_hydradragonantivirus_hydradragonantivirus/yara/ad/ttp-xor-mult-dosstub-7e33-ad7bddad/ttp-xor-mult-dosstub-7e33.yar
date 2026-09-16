rule TTP_XOR_MULT_DOSStub_7e33 {
  strings:
    $key_7e33 = { 2a 5b [2] 5e 43 [2] 19 41 [2] 5e 50 [2] 10 5c [2] 1c 56 [2] 0b 5d [2] 10 13 [2] 2d }

  condition:
    any of them
}