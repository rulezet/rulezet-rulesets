rule TTP_XOR_MULT_DOSStub_0a79 {
  strings:
    $key_0a79 = { 5e 11 [2] 2a 09 [2] 6d 0b [2] 2a 1a [2] 64 16 [2] 68 1c [2] 7f 17 [2] 64 59 [2] 59 }

  condition:
    any of them
}