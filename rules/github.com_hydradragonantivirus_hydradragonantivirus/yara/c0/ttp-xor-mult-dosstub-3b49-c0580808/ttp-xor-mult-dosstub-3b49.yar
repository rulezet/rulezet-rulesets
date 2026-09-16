rule TTP_XOR_MULT_DOSStub_3b49 {
  strings:
    $key_3b49 = { 6f 21 [2] 1b 39 [2] 5c 3b [2] 1b 2a [2] 55 26 [2] 59 2c [2] 4e 27 [2] 55 69 [2] 68 }

  condition:
    any of them
}