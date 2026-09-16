rule TTP_XOR_MULT_DOSStub_6c2b {
  strings:
    $key_6c2b = { 38 43 [2] 4c 5b [2] 0b 59 [2] 4c 48 [2] 02 44 [2] 0e 4e [2] 19 45 [2] 02 0b [2] 3f }

  condition:
    any of them
}