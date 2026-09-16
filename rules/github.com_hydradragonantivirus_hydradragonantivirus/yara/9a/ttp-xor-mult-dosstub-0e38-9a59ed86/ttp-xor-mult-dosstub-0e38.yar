rule TTP_XOR_MULT_DOSStub_0e38 {
  strings:
    $key_0e38 = { 5a 50 [2] 2e 48 [2] 69 4a [2] 2e 5b [2] 60 57 [2] 6c 5d [2] 7b 56 [2] 60 18 [2] 5d }

  condition:
    any of them
}