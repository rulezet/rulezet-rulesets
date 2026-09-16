rule TTP_XOR_MULT_DOSStub_0a7d {
  strings:
    $key_0a7d = { 5e 15 [2] 2a 0d [2] 6d 0f [2] 2a 1e [2] 64 12 [2] 68 18 [2] 7f 13 [2] 64 5d [2] 59 }

  condition:
    any of them
}