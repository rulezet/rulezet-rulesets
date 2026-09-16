rule TTP_XOR_MULT_DOSStub_3e55 {
  strings:
    $key_3e55 = { 6a 3d [2] 1e 25 [2] 59 27 [2] 1e 36 [2] 50 3a [2] 5c 30 [2] 4b 3b [2] 50 75 [2] 6d }

  condition:
    any of them
}