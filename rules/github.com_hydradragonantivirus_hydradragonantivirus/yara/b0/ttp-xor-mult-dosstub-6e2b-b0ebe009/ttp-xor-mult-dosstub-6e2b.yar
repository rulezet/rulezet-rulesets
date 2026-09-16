rule TTP_XOR_MULT_DOSStub_6e2b {
  strings:
    $key_6e2b = { 3a 43 [2] 4e 5b [2] 09 59 [2] 4e 48 [2] 00 44 [2] 0c 4e [2] 1b 45 [2] 00 0b [2] 3d }

  condition:
    any of them
}