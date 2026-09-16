rule TTP_XOR_MULT_DOSStub_694b {
  strings:
    $key_694b = { 3d 23 [2] 49 3b [2] 0e 39 [2] 49 28 [2] 07 24 [2] 0b 2e [2] 1c 25 [2] 07 6b [2] 3a }

  condition:
    any of them
}