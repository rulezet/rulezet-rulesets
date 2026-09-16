rule TTP_XOR_MULT_DOSStub_063b {
  strings:
    $key_063b = { 52 53 [2] 26 4b [2] 61 49 [2] 26 58 [2] 68 54 [2] 64 5e [2] 73 55 [2] 68 1b [2] 55 }

  condition:
    any of them
}