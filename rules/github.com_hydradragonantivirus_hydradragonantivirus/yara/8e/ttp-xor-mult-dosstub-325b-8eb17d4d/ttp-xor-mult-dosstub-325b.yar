rule TTP_XOR_MULT_DOSStub_325b {
  strings:
    $key_325b = { 66 33 [2] 12 2b [2] 55 29 [2] 12 38 [2] 5c 34 [2] 50 3e [2] 47 35 [2] 5c 7b [2] 61 }

  condition:
    any of them
}