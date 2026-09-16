rule TTP_XOR_MULT_DOSStub_1e2b {
  strings:
    $key_1e2b = { 4a 43 [2] 3e 5b [2] 79 59 [2] 3e 48 [2] 70 44 [2] 7c 4e [2] 6b 45 [2] 70 0b [2] 4d }

  condition:
    any of them
}