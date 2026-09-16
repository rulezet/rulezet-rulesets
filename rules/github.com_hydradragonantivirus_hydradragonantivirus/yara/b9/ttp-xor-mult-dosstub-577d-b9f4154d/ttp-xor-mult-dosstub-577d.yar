rule TTP_XOR_MULT_DOSStub_577d {
  strings:
    $key_577d = { 03 15 [2] 77 0d [2] 30 0f [2] 77 1e [2] 39 12 [2] 35 18 [2] 22 13 [2] 39 5d [2] 04 }

  condition:
    any of them
}