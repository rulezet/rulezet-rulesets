rule TTP_XOR_MULT_DOSStub_5e38 {
  strings:
    $key_5e38 = { 0a 50 [2] 7e 48 [2] 39 4a [2] 7e 5b [2] 30 57 [2] 3c 5d [2] 2b 56 [2] 30 18 [2] 0d }

  condition:
    any of them
}