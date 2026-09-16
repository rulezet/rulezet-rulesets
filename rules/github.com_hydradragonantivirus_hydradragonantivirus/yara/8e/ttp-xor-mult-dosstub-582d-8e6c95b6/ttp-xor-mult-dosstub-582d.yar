rule TTP_XOR_MULT_DOSStub_582d {
  strings:
    $key_582d = { 0c 45 [2] 78 5d [2] 3f 5f [2] 78 4e [2] 36 42 [2] 3a 48 [2] 2d 43 [2] 36 0d [2] 0b }

  condition:
    any of them
}