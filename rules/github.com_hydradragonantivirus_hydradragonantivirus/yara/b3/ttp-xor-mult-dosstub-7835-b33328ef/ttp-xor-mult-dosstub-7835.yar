rule TTP_XOR_MULT_DOSStub_7835 {
  strings:
    $key_7835 = { 2c 5d [2] 58 45 [2] 1f 47 [2] 58 56 [2] 16 5a [2] 1a 50 [2] 0d 5b [2] 16 15 [2] 2b }

  condition:
    any of them
}