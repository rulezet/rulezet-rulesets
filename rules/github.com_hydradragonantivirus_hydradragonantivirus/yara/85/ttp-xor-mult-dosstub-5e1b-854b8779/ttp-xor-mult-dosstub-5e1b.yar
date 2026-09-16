rule TTP_XOR_MULT_DOSStub_5e1b {
  strings:
    $key_5e1b = { 0a 73 [2] 7e 6b [2] 39 69 [2] 7e 78 [2] 30 74 [2] 3c 7e [2] 2b 75 [2] 30 3b [2] 0d }

  condition:
    any of them
}