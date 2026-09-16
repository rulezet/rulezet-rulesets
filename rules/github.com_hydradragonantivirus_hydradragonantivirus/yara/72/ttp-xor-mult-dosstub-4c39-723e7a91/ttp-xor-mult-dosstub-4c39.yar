rule TTP_XOR_MULT_DOSStub_4c39 {
  strings:
    $key_4c39 = { 18 51 [2] 6c 49 [2] 2b 4b [2] 6c 5a [2] 22 56 [2] 2e 5c [2] 39 57 [2] 22 19 [2] 1f }

  condition:
    any of them
}