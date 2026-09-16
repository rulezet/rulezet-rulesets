rule TTP_XOR_MULT_DOSStub_4422 {
  strings:
    $key_4422 = { 10 4a [2] 64 52 [2] 23 50 [2] 64 41 [2] 2a 4d [2] 26 47 [2] 31 4c [2] 2a 02 [2] 17 }

  condition:
    any of them
}