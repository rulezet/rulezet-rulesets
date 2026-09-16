rule TTP_XOR_MULT_DOSStub_727d {
  strings:
    $key_727d = { 26 15 [2] 52 0d [2] 15 0f [2] 52 1e [2] 1c 12 [2] 10 18 [2] 07 13 [2] 1c 5d [2] 21 }

  condition:
    any of them
}