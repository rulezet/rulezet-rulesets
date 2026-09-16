rule TTP_XOR_MULT_DOSStub_4404 {
  strings:
    $key_4404 = { 10 6c [2] 64 74 [2] 23 76 [2] 64 67 [2] 2a 6b [2] 26 61 [2] 31 6a [2] 2a 24 [2] 17 }

  condition:
    any of them
}