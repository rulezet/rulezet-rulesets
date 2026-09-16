rule TTP_XOR_MULT_DOSStub_0a1b {
  strings:
    $key_0a1b = { 5e 73 [2] 2a 6b [2] 6d 69 [2] 2a 78 [2] 64 74 [2] 68 7e [2] 7f 75 [2] 64 3b [2] 59 }

  condition:
    any of them
}