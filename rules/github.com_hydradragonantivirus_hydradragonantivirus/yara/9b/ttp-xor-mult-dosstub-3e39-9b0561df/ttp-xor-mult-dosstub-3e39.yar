rule TTP_XOR_MULT_DOSStub_3e39 {
  strings:
    $key_3e39 = { 6a 51 [2] 1e 49 [2] 59 4b [2] 1e 5a [2] 50 56 [2] 5c 5c [2] 4b 57 [2] 50 19 [2] 6d }

  condition:
    any of them
}