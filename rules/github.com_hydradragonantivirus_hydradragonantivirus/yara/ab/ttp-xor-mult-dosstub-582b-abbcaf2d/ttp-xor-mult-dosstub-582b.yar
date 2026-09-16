rule TTP_XOR_MULT_DOSStub_582b {
  strings:
    $key_582b = { 0c 43 [2] 78 5b [2] 3f 59 [2] 78 48 [2] 36 44 [2] 3a 4e [2] 2d 45 [2] 36 0b [2] 0b }

  condition:
    any of them
}