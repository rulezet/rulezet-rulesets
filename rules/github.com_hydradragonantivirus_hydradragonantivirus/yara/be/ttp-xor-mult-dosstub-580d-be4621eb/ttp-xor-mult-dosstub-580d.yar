rule TTP_XOR_MULT_DOSStub_580d {
  strings:
    $key_580d = { 0c 65 [2] 78 7d [2] 3f 7f [2] 78 6e [2] 36 62 [2] 3a 68 [2] 2d 63 [2] 36 2d [2] 0b }

  condition:
    any of them
}