rule TTP_XOR_MULT_DOSStub_6a0b {
  strings:
    $key_6a0b = { 3e 63 [2] 4a 7b [2] 0d 79 [2] 4a 68 [2] 04 64 [2] 08 6e [2] 1f 65 [2] 04 2b [2] 39 }

  condition:
    any of them
}