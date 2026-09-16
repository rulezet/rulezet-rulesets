rule TTP_XOR_MULT_DOSStub_637d {
  strings:
    $key_637d = { 37 15 [2] 43 0d [2] 04 0f [2] 43 1e [2] 0d 12 [2] 01 18 [2] 16 13 [2] 0d 5d [2] 30 }

  condition:
    any of them
}