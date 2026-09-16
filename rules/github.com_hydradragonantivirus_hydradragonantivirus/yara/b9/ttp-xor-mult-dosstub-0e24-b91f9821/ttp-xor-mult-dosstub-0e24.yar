rule TTP_XOR_MULT_DOSStub_0e24 {
  strings:
    $key_0e24 = { 5a 4c [2] 2e 54 [2] 69 56 [2] 2e 47 [2] 60 4b [2] 6c 41 [2] 7b 4a [2] 60 04 [2] 5d }

  condition:
    any of them
}