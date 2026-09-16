rule TTP_XOR_MULT_DOSStub_0a0b {
  strings:
    $key_0a0b = { 5e 63 [2] 2a 7b [2] 6d 79 [2] 2a 68 [2] 64 64 [2] 68 6e [2] 7f 65 [2] 64 2b [2] 59 }

  condition:
    any of them
}