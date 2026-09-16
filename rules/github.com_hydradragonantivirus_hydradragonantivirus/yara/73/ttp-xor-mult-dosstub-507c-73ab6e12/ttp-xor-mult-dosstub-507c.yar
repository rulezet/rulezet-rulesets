rule TTP_XOR_MULT_DOSStub_507c {
  strings:
    $key_507c = { 04 14 [2] 70 0c [2] 37 0e [2] 70 1f [2] 3e 13 [2] 32 19 [2] 25 12 [2] 3e 5c [2] 03 }

  condition:
    any of them
}