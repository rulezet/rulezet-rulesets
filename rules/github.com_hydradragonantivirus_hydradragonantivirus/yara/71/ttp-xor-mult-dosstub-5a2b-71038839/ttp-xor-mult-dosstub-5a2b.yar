rule TTP_XOR_MULT_DOSStub_5a2b {
  strings:
    $key_5a2b = { 0e 43 [2] 7a 5b [2] 3d 59 [2] 7a 48 [2] 34 44 [2] 38 4e [2] 2f 45 [2] 34 0b [2] 09 }

  condition:
    any of them
}