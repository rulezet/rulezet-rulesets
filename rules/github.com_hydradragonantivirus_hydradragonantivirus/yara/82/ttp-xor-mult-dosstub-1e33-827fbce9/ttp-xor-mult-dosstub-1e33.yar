rule TTP_XOR_MULT_DOSStub_1e33 {
  strings:
    $key_1e33 = { 4a 5b [2] 3e 43 [2] 79 41 [2] 3e 50 [2] 70 5c [2] 7c 56 [2] 6b 5d [2] 70 13 [2] 4d }

  condition:
    any of them
}