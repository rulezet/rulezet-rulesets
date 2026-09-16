rule TTP_XOR_MULT_DOSStub_2575 {
  strings:
    $key_2575 = { 71 1d [2] 05 05 [2] 42 07 [2] 05 16 [2] 4b 1a [2] 47 10 [2] 50 1b [2] 4b 55 [2] 76 }

  condition:
    any of them
}