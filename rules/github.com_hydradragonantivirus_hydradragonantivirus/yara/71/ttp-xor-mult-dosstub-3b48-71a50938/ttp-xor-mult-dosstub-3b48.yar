rule TTP_XOR_MULT_DOSStub_3b48 {
  strings:
    $key_3b48 = { 6f 20 [2] 1b 38 [2] 5c 3a [2] 1b 2b [2] 55 27 [2] 59 2d [2] 4e 26 [2] 55 68 [2] 68 }

  condition:
    any of them
}