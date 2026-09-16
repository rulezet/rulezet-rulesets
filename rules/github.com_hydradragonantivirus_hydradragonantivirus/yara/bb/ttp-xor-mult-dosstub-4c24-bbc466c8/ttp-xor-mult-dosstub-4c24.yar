rule TTP_XOR_MULT_DOSStub_4c24 {
  strings:
    $key_4c24 = { 18 4c [2] 6c 54 [2] 2b 56 [2] 6c 47 [2] 22 4b [2] 2e 41 [2] 39 4a [2] 22 04 [2] 1f }

  condition:
    any of them
}