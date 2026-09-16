rule TTP_XOR_MULT_DOSStub_790b {
  strings:
    $key_790b = { 2d 63 [2] 59 7b [2] 1e 79 [2] 59 68 [2] 17 64 [2] 1b 6e [2] 0c 65 [2] 17 2b [2] 2a }

  condition:
    any of them
}