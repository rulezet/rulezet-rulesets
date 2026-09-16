rule TTP_XOR_MULT_DOSStub_3e34 {
  strings:
    $key_3e34 = { 6a 5c [2] 1e 44 [2] 59 46 [2] 1e 57 [2] 50 5b [2] 5c 51 [2] 4b 5a [2] 50 14 [2] 6d }

  condition:
    any of them
}