rule TTP_XOR_MULT_DOSStub_627d {
  strings:
    $key_627d = { 36 15 [2] 42 0d [2] 05 0f [2] 42 1e [2] 0c 12 [2] 00 18 [2] 17 13 [2] 0c 5d [2] 31 }

  condition:
    any of them
}