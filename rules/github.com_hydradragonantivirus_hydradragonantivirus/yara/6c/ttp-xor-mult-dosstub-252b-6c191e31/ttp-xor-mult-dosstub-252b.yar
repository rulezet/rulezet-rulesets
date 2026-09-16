rule TTP_XOR_MULT_DOSStub_252b {
  strings:
    $key_252b = { 71 43 [2] 05 5b [2] 42 59 [2] 05 48 [2] 4b 44 [2] 47 4e [2] 50 45 [2] 4b 0b [2] 76 }

  condition:
    any of them
}