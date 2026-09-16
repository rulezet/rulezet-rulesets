rule TTP_XOR_MULT_DOSStub_3835 {
  strings:
    $key_3835 = { 6c 5d [2] 18 45 [2] 5f 47 [2] 18 56 [2] 56 5a [2] 5a 50 [2] 4d 5b [2] 56 15 [2] 6b }

  condition:
    any of them
}