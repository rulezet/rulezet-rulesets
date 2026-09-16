rule TTP_XOR_MULT_DOSStub_431b {
  strings:
    $key_431b = { 17 73 [2] 63 6b [2] 24 69 [2] 63 78 [2] 2d 74 [2] 21 7e [2] 36 75 [2] 2d 3b [2] 10 }

  condition:
    any of them
}