rule TTP_XOR_MULT_DOSStub_395b {
  strings:
    $key_395b = { 6d 33 [2] 19 2b [2] 5e 29 [2] 19 38 [2] 57 34 [2] 5b 3e [2] 4c 35 [2] 57 7b [2] 6a }

  condition:
    any of them
}