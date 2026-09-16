rule TTP_XOR_MULT_DOSStub_1e29 {
  strings:
    $key_1e29 = { 4a 41 [2] 3e 59 [2] 79 5b [2] 3e 4a [2] 70 46 [2] 7c 4c [2] 6b 47 [2] 70 09 [2] 4d }

  condition:
    any of them
}