rule TTP_XOR_MULT_DOSStub_0322 {
  strings:
    $key_0322 = { 57 4a [2] 23 52 [2] 64 50 [2] 23 41 [2] 6d 4d [2] 61 47 [2] 76 4c [2] 6d 02 [2] 50 }

  condition:
    any of them
}