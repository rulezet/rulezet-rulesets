rule TTP_XOR_MULT_DOSStub_3afb {
  strings:
    $key_3afb = { 6e 93 [2] 1a 8b [2] 5d 89 [2] 1a 98 [2] 54 94 [2] 58 9e [2] 4f 95 [2] 54 db [2] 69 }

  condition:
    any of them
}