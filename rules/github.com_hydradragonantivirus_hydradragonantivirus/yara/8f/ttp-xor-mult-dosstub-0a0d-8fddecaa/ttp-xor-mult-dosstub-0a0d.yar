rule TTP_XOR_MULT_DOSStub_0a0d {
  strings:
    $key_0a0d = { 5e 65 [2] 2a 7d [2] 6d 7f [2] 2a 6e [2] 64 62 [2] 68 68 [2] 7f 63 [2] 64 2d [2] 59 }

  condition:
    any of them
}