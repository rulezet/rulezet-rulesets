rule TTP_XOR_MULT_DOSStub_4929 {
  strings:
    $key_4929 = { 1d 41 [2] 69 59 [2] 2e 5b [2] 69 4a [2] 27 46 [2] 2b 4c [2] 3c 47 [2] 27 09 [2] 1a }

  condition:
    any of them
}