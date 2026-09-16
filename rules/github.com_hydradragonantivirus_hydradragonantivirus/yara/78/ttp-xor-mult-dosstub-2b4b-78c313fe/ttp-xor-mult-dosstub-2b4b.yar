rule TTP_XOR_MULT_DOSStub_2b4b {
  strings:
    $key_2b4b = { 7f 23 [2] 0b 3b [2] 4c 39 [2] 0b 28 [2] 45 24 [2] 49 2e [2] 5e 25 [2] 45 6b [2] 78 }

  condition:
    any of them
}