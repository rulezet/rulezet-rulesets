rule TTP_XOR_MULT_DOSStub_4f35 {
  strings:
    $key_4f35 = { 1b 5d [2] 6f 45 [2] 28 47 [2] 6f 56 [2] 21 5a [2] 2d 50 [2] 3a 5b [2] 21 15 [2] 1c }

  condition:
    any of them
}