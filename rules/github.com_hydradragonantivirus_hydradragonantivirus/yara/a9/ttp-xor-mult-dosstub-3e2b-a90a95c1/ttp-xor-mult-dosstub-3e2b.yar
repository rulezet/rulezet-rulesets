rule TTP_XOR_MULT_DOSStub_3e2b {
  strings:
    $key_3e2b = { 6a 43 [2] 1e 5b [2] 59 59 [2] 1e 48 [2] 50 44 [2] 5c 4e [2] 4b 45 [2] 50 0b [2] 6d }

  condition:
    any of them
}