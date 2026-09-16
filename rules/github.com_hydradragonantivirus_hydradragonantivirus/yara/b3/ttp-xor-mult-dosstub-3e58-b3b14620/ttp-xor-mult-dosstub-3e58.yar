rule TTP_XOR_MULT_DOSStub_3e58 {
  strings:
    $key_3e58 = { 6a 30 [2] 1e 28 [2] 59 2a [2] 1e 3b [2] 50 37 [2] 5c 3d [2] 4b 36 [2] 50 78 [2] 6d }

  condition:
    any of them
}