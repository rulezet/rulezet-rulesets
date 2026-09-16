rule TTP_XOR_MULT_DOSStub_5e3b {
  strings:
    $key_5e3b = { 0a 53 [2] 7e 4b [2] 39 49 [2] 7e 58 [2] 30 54 [2] 3c 5e [2] 2b 55 [2] 30 1b [2] 0d }

  condition:
    any of them
}