rule TTP_XOR_MULT_DOSStub_6e5b {
  strings:
    $key_6e5b = { 3a 33 [2] 4e 2b [2] 09 29 [2] 4e 38 [2] 00 34 [2] 0c 3e [2] 1b 35 [2] 00 7b [2] 3d }

  condition:
    any of them
}