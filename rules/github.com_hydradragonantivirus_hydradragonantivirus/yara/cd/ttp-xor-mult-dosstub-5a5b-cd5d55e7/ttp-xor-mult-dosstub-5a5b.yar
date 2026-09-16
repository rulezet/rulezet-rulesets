rule TTP_XOR_MULT_DOSStub_5a5b {
  strings:
    $key_5a5b = { 0e 33 [2] 7a 2b [2] 3d 29 [2] 7a 38 [2] 34 34 [2] 38 3e [2] 2f 35 [2] 34 7b [2] 09 }

  condition:
    any of them
}