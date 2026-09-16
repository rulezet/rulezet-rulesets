rule TTP_XOR_MULT_DOSStub_770d {
  strings:
    $key_770d = { 23 65 [2] 57 7d [2] 10 7f [2] 57 6e [2] 19 62 [2] 15 68 [2] 02 63 [2] 19 2d [2] 24 }

  condition:
    any of them
}