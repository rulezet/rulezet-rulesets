rule TTP_XOR_MULT_DOSStub_3b75 {
  strings:
    $key_3b75 = { 6f 1d [2] 1b 05 [2] 5c 07 [2] 1b 16 [2] 55 1a [2] 59 10 [2] 4e 1b [2] 55 55 [2] 68 }

  condition:
    any of them
}