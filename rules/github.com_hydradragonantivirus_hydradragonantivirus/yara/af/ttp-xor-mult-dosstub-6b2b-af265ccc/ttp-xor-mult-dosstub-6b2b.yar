rule TTP_XOR_MULT_DOSStub_6b2b {
  strings:
    $key_6b2b = { 3f 43 [2] 4b 5b [2] 0c 59 [2] 4b 48 [2] 05 44 [2] 09 4e [2] 1e 45 [2] 05 0b [2] 38 }

  condition:
    any of them
}