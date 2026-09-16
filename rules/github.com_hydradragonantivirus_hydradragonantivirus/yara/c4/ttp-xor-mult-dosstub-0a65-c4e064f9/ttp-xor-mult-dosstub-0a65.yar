rule TTP_XOR_MULT_DOSStub_0a65 {
  strings:
    $key_0a65 = { 5e 0d [2] 2a 15 [2] 6d 17 [2] 2a 06 [2] 64 0a [2] 68 00 [2] 7f 0b [2] 64 45 [2] 59 }

  condition:
    any of them
}