rule TTP_XOR_MULT_DOSStub_501b {
  strings:
    $key_501b = { 04 73 [2] 70 6b [2] 37 69 [2] 70 78 [2] 3e 74 [2] 32 7e [2] 25 75 [2] 3e 3b [2] 03 }

  condition:
    any of them
}