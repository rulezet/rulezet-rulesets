rule TTP_XOR_MULT_DOSStub_166d {
  strings:
    $key_166d = { 42 05 [2] 36 1d [2] 71 1f [2] 36 0e [2] 78 02 [2] 74 08 [2] 63 03 [2] 78 4d [2] 45 }

  condition:
    any of them
}