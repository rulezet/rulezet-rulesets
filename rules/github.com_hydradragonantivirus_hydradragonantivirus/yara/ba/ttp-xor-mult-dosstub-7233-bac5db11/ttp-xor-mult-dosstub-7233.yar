rule TTP_XOR_MULT_DOSStub_7233 {
  strings:
    $key_7233 = { 26 5b [2] 52 43 [2] 15 41 [2] 52 50 [2] 1c 5c [2] 10 56 [2] 07 5d [2] 1c 13 [2] 21 }

  condition:
    any of them
}