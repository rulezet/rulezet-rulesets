rule TTP_XOR_MULT_DOSStub_0335 {
  strings:
    $key_0335 = { 57 5d [2] 23 45 [2] 64 47 [2] 23 56 [2] 6d 5a [2] 61 50 [2] 76 5b [2] 6d 15 [2] 50 }

  condition:
    any of them
}