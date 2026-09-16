rule TTP_XOR_MULT_DOSStub_3e54 {
  strings:
    $key_3e54 = { 6a 3c [2] 1e 24 [2] 59 26 [2] 1e 37 [2] 50 3b [2] 5c 31 [2] 4b 3a [2] 50 74 [2] 6d }

  condition:
    any of them
}