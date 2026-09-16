rule TTP_XOR_MULT_DOSStub_137b {
  strings:
    $key_137b = { 47 13 [2] 33 0b [2] 74 09 [2] 33 18 [2] 7d 14 [2] 71 1e [2] 66 15 [2] 7d 5b [2] 40 }

  condition:
    any of them
}