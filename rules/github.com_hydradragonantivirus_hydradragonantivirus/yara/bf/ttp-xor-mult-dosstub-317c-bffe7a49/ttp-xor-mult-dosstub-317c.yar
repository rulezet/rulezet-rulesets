rule TTP_XOR_MULT_DOSStub_317c {
  strings:
    $key_317c = { 65 14 [2] 11 0c [2] 56 0e [2] 11 1f [2] 5f 13 [2] 53 19 [2] 44 12 [2] 5f 5c [2] 62 }

  condition:
    any of them
}