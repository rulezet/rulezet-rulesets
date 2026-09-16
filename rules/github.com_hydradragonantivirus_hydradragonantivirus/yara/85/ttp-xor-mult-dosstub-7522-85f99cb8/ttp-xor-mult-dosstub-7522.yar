rule TTP_XOR_MULT_DOSStub_7522 {
  strings:
    $key_7522 = { 21 4a [2] 55 52 [2] 12 50 [2] 55 41 [2] 1b 4d [2] 17 47 [2] 00 4c [2] 1b 02 [2] 26 }

  condition:
    any of them
}