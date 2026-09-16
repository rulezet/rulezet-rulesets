rule TTP_XOR_MULT_DOSStub_0e22 {
  strings:
    $key_0e22 = { 5a 4a [2] 2e 52 [2] 69 50 [2] 2e 41 [2] 60 4d [2] 6c 47 [2] 7b 4c [2] 60 02 [2] 5d }

  condition:
    any of them
}