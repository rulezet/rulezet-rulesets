rule TTP_XOR_MULT_DOSStub_571a {
  strings:
    $key_571a = { 03 72 [2] 77 6a [2] 30 68 [2] 77 79 [2] 39 75 [2] 35 7f [2] 22 74 [2] 39 3a [2] 04 }

  condition:
    any of them
}