rule TTP_XOR_MULT_DOSStub_061b {
  strings:
    $key_061b = { 52 73 [2] 26 6b [2] 61 69 [2] 26 78 [2] 68 74 [2] 64 7e [2] 73 75 [2] 68 3b [2] 55 }

  condition:
    any of them
}