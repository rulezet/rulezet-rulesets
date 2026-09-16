rule TTP_XOR_MULT_DOSStub_5575 {
  strings:
    $key_5575 = { 01 1d [2] 75 05 [2] 32 07 [2] 75 16 [2] 3b 1a [2] 37 10 [2] 20 1b [2] 3b 55 [2] 06 }

  condition:
    any of them
}