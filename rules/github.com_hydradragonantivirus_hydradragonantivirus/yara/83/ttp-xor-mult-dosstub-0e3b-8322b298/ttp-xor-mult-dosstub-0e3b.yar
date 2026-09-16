rule TTP_XOR_MULT_DOSStub_0e3b {
  strings:
    $key_0e3b = { 5a 53 [2] 2e 4b [2] 69 49 [2] 2e 58 [2] 60 54 [2] 6c 5e [2] 7b 55 [2] 60 1b [2] 5d }

  condition:
    any of them
}