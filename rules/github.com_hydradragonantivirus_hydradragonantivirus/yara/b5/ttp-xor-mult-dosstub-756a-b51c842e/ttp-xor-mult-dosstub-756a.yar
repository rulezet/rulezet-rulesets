rule TTP_XOR_MULT_DOSStub_756a {
  strings:
    $key_756a = { 21 02 [2] 55 1a [2] 12 18 [2] 55 09 [2] 1b 05 [2] 17 0f [2] 00 04 [2] 1b 4a [2] 26 }

  condition:
    any of them
}