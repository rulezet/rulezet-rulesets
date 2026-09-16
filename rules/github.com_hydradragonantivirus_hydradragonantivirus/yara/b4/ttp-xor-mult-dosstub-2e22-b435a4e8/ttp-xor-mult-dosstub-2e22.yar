rule TTP_XOR_MULT_DOSStub_2e22 {
  strings:
    $key_2e22 = { 7a 4a [2] 0e 52 [2] 49 50 [2] 0e 41 [2] 40 4d [2] 4c 47 [2] 5b 4c [2] 40 02 [2] 7d }

  condition:
    any of them
}