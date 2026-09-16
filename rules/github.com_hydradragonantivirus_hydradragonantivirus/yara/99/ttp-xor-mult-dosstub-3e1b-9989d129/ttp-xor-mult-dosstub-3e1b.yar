rule TTP_XOR_MULT_DOSStub_3e1b {
  strings:
    $key_3e1b = { 6a 73 [2] 1e 6b [2] 59 69 [2] 1e 78 [2] 50 74 [2] 5c 7e [2] 4b 75 [2] 50 3b [2] 6d }

  condition:
    any of them
}