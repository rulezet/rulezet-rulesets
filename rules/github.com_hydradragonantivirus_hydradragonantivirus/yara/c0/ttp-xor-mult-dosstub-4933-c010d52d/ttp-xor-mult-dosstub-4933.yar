rule TTP_XOR_MULT_DOSStub_4933 {
  strings:
    $key_4933 = { 1d 5b [2] 69 43 [2] 2e 41 [2] 69 50 [2] 27 5c [2] 2b 56 [2] 3c 5d [2] 27 13 [2] 1a }

  condition:
    any of them
}