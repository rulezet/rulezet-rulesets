rule TTP_XOR_MULT_DOSStub_0d0b {
  strings:
    $key_0d0b = { 59 63 [2] 2d 7b [2] 6a 79 [2] 2d 68 [2] 63 64 [2] 6f 6e [2] 78 65 [2] 63 2b [2] 5e }

  condition:
    any of them
}