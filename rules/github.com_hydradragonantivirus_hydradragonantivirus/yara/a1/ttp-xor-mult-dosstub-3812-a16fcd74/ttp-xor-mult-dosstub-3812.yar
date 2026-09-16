rule TTP_XOR_MULT_DOSStub_3812 {
  strings:
    $key_3812 = { 6c 7a [2] 18 62 [2] 5f 60 [2] 18 71 [2] 56 7d [2] 5a 77 [2] 4d 7c [2] 56 32 [2] 6b }

  condition:
    any of them
}