rule TTP_XOR_MULT_DOSStub_7a73 {
  strings:
    $key_7a73 = { 2e 1b [2] 5a 03 [2] 1d 01 [2] 5a 10 [2] 14 1c [2] 18 16 [2] 0f 1d [2] 14 53 [2] 29 }

  condition:
    any of them
}