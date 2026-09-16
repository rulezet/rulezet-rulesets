rule TTP_XOR_MULT_DOSStub_4939 {
  strings:
    $key_4939 = { 1d 51 [2] 69 49 [2] 2e 4b [2] 69 5a [2] 27 56 [2] 2b 5c [2] 3c 57 [2] 27 19 [2] 1a }

  condition:
    any of them
}