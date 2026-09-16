rule TTP_XOR_MULT_DOSStub_120b {
  strings:
    $key_120b = { 46 63 [2] 32 7b [2] 75 79 [2] 32 68 [2] 7c 64 [2] 70 6e [2] 67 65 [2] 7c 2b [2] 41 }

  condition:
    any of them
}