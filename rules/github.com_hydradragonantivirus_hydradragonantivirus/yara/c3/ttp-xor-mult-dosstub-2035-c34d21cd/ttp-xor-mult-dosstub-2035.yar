rule TTP_XOR_MULT_DOSStub_2035 {
  strings:
    $key_2035 = { 74 5d [2] 00 45 [2] 47 47 [2] 00 56 [2] 4e 5a [2] 42 50 [2] 55 5b [2] 4e 15 [2] 73 }

  condition:
    any of them
}