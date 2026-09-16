rule TTP_XOR_MULT_DOSStub_4335 {
  strings:
    $key_4335 = { 17 5d [2] 63 45 [2] 24 47 [2] 63 56 [2] 2d 5a [2] 21 50 [2] 36 5b [2] 2d 15 [2] 10 }

  condition:
    any of them
}