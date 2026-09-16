rule TTP_XOR_MULT_DOSStub_0a48 {
  strings:
    $key_0a48 = { 5e 20 [2] 2a 38 [2] 6d 3a [2] 2a 2b [2] 64 27 [2] 68 2d [2] 7f 26 [2] 64 68 [2] 59 }

  condition:
    any of them
}