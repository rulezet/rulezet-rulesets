rule TTP_XOR_MULT_DOSStub_7d73 {
  strings:
    $key_7d73 = { 29 1b [2] 5d 03 [2] 1a 01 [2] 5d 10 [2] 13 1c [2] 1f 16 [2] 08 1d [2] 13 53 [2] 2e }

  condition:
    any of them
}