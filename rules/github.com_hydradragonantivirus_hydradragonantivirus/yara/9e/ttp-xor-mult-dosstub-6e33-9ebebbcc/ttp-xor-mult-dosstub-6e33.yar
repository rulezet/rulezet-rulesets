rule TTP_XOR_MULT_DOSStub_6e33 {
  strings:
    $key_6e33 = { 3a 5b [2] 4e 43 [2] 09 41 [2] 4e 50 [2] 00 5c [2] 0c 56 [2] 1b 5d [2] 00 13 [2] 3d }

  condition:
    any of them
}