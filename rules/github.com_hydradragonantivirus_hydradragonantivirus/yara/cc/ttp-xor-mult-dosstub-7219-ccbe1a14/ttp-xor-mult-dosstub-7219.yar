rule TTP_XOR_MULT_DOSStub_7219 {
  strings:
    $key_7219 = { 26 71 [2] 52 69 [2] 15 6b [2] 52 7a [2] 1c 76 [2] 10 7c [2] 07 77 [2] 1c 39 [2] 21 }

  condition:
    any of them
}