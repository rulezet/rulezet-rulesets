rule TTP_XOR_MULT_DOSStub_137d {
  strings:
    $key_137d = { 47 15 [2] 33 0d [2] 74 0f [2] 33 1e [2] 7d 12 [2] 71 18 [2] 66 13 [2] 7d 5d [2] 40 }

  condition:
    any of them
}