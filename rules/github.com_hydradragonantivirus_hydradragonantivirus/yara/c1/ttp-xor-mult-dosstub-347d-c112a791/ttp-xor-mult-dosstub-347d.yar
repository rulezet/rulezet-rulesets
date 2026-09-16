rule TTP_XOR_MULT_DOSStub_347d {
  strings:
    $key_347d = { 60 15 [2] 14 0d [2] 53 0f [2] 14 1e [2] 5a 12 [2] 56 18 [2] 41 13 [2] 5a 5d [2] 67 }

  condition:
    any of them
}