rule TTP_XOR_MULT_DOSStub_3e38 {
  strings:
    $key_3e38 = { 6a 50 [2] 1e 48 [2] 59 4a [2] 1e 5b [2] 50 57 [2] 5c 5d [2] 4b 56 [2] 50 18 [2] 6d }

  condition:
    any of them
}