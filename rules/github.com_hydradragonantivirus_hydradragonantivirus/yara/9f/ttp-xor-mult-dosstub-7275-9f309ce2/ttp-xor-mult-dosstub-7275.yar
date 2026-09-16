rule TTP_XOR_MULT_DOSStub_7275 {
  strings:
    $key_7275 = { 26 1d [2] 52 05 [2] 15 07 [2] 52 16 [2] 1c 1a [2] 10 10 [2] 07 1b [2] 1c 55 [2] 21 }

  condition:
    any of them
}