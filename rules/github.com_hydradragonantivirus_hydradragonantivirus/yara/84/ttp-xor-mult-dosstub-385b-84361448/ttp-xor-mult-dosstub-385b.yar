rule TTP_XOR_MULT_DOSStub_385b {
  strings:
    $key_385b = { 6c 33 [2] 18 2b [2] 5f 29 [2] 18 38 [2] 56 34 [2] 5a 3e [2] 4d 35 [2] 56 7b [2] 6b }

  condition:
    any of them
}