rule TTP_XOR_MULT_DOSStub_157d {
  strings:
    $key_157d = { 41 15 [2] 35 0d [2] 72 0f [2] 35 1e [2] 7b 12 [2] 77 18 [2] 60 13 [2] 7b 5d [2] 46 }

  condition:
    any of them
}