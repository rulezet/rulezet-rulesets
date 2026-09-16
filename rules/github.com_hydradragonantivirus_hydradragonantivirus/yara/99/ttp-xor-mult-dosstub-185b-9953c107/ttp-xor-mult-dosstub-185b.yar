rule TTP_XOR_MULT_DOSStub_185b {
  strings:
    $key_185b = { 4c 33 [2] 38 2b [2] 7f 29 [2] 38 38 [2] 76 34 [2] 7a 3e [2] 6d 35 [2] 76 7b [2] 4b }

  condition:
    any of them
}