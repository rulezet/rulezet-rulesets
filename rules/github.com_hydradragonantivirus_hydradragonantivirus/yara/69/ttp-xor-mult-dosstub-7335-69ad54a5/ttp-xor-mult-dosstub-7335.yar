rule TTP_XOR_MULT_DOSStub_7335 {
  strings:
    $key_7335 = { 27 5d [2] 53 45 [2] 14 47 [2] 53 56 [2] 1d 5a [2] 11 50 [2] 06 5b [2] 1d 15 [2] 20 }

  condition:
    any of them
}