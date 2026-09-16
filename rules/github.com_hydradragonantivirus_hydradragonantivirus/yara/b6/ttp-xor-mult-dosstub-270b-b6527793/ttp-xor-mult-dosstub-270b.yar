rule TTP_XOR_MULT_DOSStub_270b {
  strings:
    $key_270b = { 73 63 [2] 07 7b [2] 40 79 [2] 07 68 [2] 49 64 [2] 45 6e [2] 52 65 [2] 49 2b [2] 74 }

  condition:
    any of them
}