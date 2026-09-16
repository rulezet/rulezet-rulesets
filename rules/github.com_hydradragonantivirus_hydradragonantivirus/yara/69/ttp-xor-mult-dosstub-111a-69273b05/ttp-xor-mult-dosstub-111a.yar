rule TTP_XOR_MULT_DOSStub_111a {
  strings:
    $key_111a = { 45 72 [2] 31 6a [2] 76 68 [2] 31 79 [2] 7f 75 [2] 73 7f [2] 64 74 [2] 7f 3a [2] 42 }

  condition:
    any of them
}