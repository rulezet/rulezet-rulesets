rule TTP_XOR_MULT_DOSStub_5e35 {
  strings:
    $key_5e35 = { 0a 5d [2] 7e 45 [2] 39 47 [2] 7e 56 [2] 30 5a [2] 3c 50 [2] 2b 5b [2] 30 15 [2] 0d }

  condition:
    any of them
}