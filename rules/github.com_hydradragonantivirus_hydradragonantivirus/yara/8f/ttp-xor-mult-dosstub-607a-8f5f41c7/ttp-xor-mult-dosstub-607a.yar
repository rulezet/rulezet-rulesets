rule TTP_XOR_MULT_DOSStub_607a {
  strings:
    $key_607a = { 34 12 [2] 40 0a [2] 07 08 [2] 40 19 [2] 0e 15 [2] 02 1f [2] 15 14 [2] 0e 5a [2] 33 }

  condition:
    any of them
}