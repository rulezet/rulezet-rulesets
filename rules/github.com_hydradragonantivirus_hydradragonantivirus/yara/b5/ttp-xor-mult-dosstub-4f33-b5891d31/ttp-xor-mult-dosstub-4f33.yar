rule TTP_XOR_MULT_DOSStub_4f33 {
  strings:
    $key_4f33 = { 1b 5b [2] 6f 43 [2] 28 41 [2] 6f 50 [2] 21 5c [2] 2d 56 [2] 3a 5d [2] 21 13 [2] 1c }

  condition:
    any of them
}