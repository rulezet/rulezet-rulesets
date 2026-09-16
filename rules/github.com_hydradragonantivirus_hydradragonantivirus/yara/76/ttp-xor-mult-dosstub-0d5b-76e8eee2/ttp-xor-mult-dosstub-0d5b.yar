rule TTP_XOR_MULT_DOSStub_0d5b {
  strings:
    $key_0d5b = { 59 33 [2] 2d 2b [2] 6a 29 [2] 2d 38 [2] 63 34 [2] 6f 3e [2] 78 35 [2] 63 7b [2] 5e }

  condition:
    any of them
}