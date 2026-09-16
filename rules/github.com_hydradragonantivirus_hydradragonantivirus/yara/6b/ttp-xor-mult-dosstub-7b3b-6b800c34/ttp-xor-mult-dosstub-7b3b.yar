rule TTP_XOR_MULT_DOSStub_7b3b {
  strings:
    $key_7b3b = { 2f 53 [2] 5b 4b [2] 1c 49 [2] 5b 58 [2] 15 54 [2] 19 5e [2] 0e 55 [2] 15 1b [2] 28 }

  condition:
    any of them
}