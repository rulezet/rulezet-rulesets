rule TTP_XOR_MULT_DOSStub_6d0b {
  strings:
    $key_6d0b = { 39 63 [2] 4d 7b [2] 0a 79 [2] 4d 68 [2] 03 64 [2] 0f 6e [2] 18 65 [2] 03 2b [2] 3e }

  condition:
    any of them
}