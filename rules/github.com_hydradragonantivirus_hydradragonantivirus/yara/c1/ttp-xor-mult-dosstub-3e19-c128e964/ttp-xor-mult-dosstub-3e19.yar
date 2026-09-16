rule TTP_XOR_MULT_DOSStub_3e19 {
  strings:
    $key_3e19 = { 6a 71 [2] 1e 69 [2] 59 6b [2] 1e 7a [2] 50 76 [2] 5c 7c [2] 4b 77 [2] 50 39 [2] 6d }

  condition:
    any of them
}