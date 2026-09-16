rule TTP_XOR_MULT_DOSStub_582c {
  strings:
    $key_582c = { 0c 44 [2] 78 5c [2] 3f 5e [2] 78 4f [2] 36 43 [2] 3a 49 [2] 2d 42 [2] 36 0c [2] 0b }

  condition:
    any of them
}