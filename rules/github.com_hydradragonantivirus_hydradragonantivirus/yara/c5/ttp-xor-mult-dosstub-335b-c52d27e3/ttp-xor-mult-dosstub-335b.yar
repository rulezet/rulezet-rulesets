rule TTP_XOR_MULT_DOSStub_335b {
  strings:
    $key_335b = { 67 33 [2] 13 2b [2] 54 29 [2] 13 38 [2] 5d 34 [2] 51 3e [2] 46 35 [2] 5d 7b [2] 60 }

  condition:
    any of them
}