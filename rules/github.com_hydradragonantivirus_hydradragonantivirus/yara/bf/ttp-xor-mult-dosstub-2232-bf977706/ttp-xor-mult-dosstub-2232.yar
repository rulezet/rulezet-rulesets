rule TTP_XOR_MULT_DOSStub_2232 {
  strings:
    $key_2232 = { 76 5a [2] 02 42 [2] 45 40 [2] 02 51 [2] 4c 5d [2] 40 57 [2] 57 5c [2] 4c 12 [2] 71 }

  condition:
    any of them
}