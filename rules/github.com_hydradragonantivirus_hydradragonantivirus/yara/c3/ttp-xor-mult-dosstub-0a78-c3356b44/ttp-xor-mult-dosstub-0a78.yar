rule TTP_XOR_MULT_DOSStub_0a78 {
  strings:
    $key_0a78 = { 5e 10 [2] 2a 08 [2] 6d 0a [2] 2a 1b [2] 64 17 [2] 68 1d [2] 7f 16 [2] 64 58 [2] 59 }

  condition:
    any of them
}