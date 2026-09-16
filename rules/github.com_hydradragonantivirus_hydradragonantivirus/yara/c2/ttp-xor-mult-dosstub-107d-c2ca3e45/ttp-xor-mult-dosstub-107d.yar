rule TTP_XOR_MULT_DOSStub_107d {
  strings:
    $key_107d = { 44 15 [2] 30 0d [2] 77 0f [2] 30 1e [2] 7e 12 [2] 72 18 [2] 65 13 [2] 7e 5d [2] 43 }

  condition:
    any of them
}