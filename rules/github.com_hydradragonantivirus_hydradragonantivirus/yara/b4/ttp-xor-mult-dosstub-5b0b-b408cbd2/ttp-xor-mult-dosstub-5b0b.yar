rule TTP_XOR_MULT_DOSStub_5b0b {
  strings:
    $key_5b0b = { 0f 63 [2] 7b 7b [2] 3c 79 [2] 7b 68 [2] 35 64 [2] 39 6e [2] 2e 65 [2] 35 2b [2] 08 }

  condition:
    any of them
}