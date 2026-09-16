rule TTP_XOR_MULT_DOSStub_114a {
  strings:
    $key_114a = { 45 22 [2] 31 3a [2] 76 38 [2] 31 29 [2] 7f 25 [2] 73 2f [2] 64 24 [2] 7f 6a [2] 42 }

  condition:
    any of them
}