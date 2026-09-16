rule TTP_XOR_MULT_DOSStub_137c {
  strings:
    $key_137c = { 47 14 [2] 33 0c [2] 74 0e [2] 33 1f [2] 7d 13 [2] 71 19 [2] 66 12 [2] 7d 5c [2] 40 }

  condition:
    any of them
}