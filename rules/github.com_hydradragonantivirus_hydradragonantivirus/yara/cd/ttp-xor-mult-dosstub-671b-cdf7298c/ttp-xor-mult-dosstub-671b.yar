rule TTP_XOR_MULT_DOSStub_671b {
  strings:
    $key_671b = { 33 73 [2] 47 6b [2] 00 69 [2] 47 78 [2] 09 74 [2] 05 7e [2] 12 75 [2] 09 3b [2] 34 }

  condition:
    any of them
}