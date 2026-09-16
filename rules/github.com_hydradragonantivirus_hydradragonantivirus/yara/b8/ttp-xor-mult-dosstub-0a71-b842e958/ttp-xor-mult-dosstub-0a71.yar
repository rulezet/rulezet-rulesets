rule TTP_XOR_MULT_DOSStub_0a71 {
  strings:
    $key_0a71 = { 5e 19 [2] 2a 01 [2] 6d 03 [2] 2a 12 [2] 64 1e [2] 68 14 [2] 7f 1f [2] 64 51 [2] 59 }

  condition:
    any of them
}