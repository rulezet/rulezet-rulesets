rule TTP_XOR_MULT_DOSStub_526b {
  strings:
    $key_526b = { 06 03 [2] 72 1b [2] 35 19 [2] 72 08 [2] 3c 04 [2] 30 0e [2] 27 05 [2] 3c 4b [2] 01 }

  condition:
    any of them
}