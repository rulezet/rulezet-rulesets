rule TTP_XOR_MULT_DOSStub_0a5b {
  strings:
    $key_0a5b = { 5e 33 [2] 2a 2b [2] 6d 29 [2] 2a 38 [2] 64 34 [2] 68 3e [2] 7f 35 [2] 64 7b [2] 59 }

  condition:
    any of them
}