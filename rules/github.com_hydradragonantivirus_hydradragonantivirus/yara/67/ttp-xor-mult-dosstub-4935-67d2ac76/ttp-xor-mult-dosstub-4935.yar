rule TTP_XOR_MULT_DOSStub_4935 {
  strings:
    $key_4935 = { 1d 5d [2] 69 45 [2] 2e 47 [2] 69 56 [2] 27 5a [2] 2b 50 [2] 3c 5b [2] 27 15 [2] 1a }

  condition:
    any of them
}