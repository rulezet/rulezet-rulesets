rule TTP_XOR_MULT_DOSStub_4f38 {
  strings:
    $key_4f38 = { 1b 50 [2] 6f 48 [2] 28 4a [2] 6f 5b [2] 21 57 [2] 2d 5d [2] 3a 56 [2] 21 18 [2] 1c }

  condition:
    any of them
}