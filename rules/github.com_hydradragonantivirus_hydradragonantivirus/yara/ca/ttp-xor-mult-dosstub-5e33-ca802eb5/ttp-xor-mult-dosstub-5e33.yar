rule TTP_XOR_MULT_DOSStub_5e33 {
  strings:
    $key_5e33 = { 0a 5b [2] 7e 43 [2] 39 41 [2] 7e 50 [2] 30 5c [2] 3c 56 [2] 2b 5d [2] 30 13 [2] 0d }

  condition:
    any of them
}