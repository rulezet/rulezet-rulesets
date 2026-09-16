rule TTP_XOR_MULT_DOSStub_757f {
  strings:
    $key_757f = { 21 17 [2] 55 0f [2] 12 0d [2] 55 1c [2] 1b 10 [2] 17 1a [2] 00 11 [2] 1b 5f [2] 26 }

  condition:
    any of them
}