rule TTP_XOR_MULT_DOSStub_1f0d {
  strings:
    $key_1f0d = { 4b 65 [2] 3f 7d [2] 78 7f [2] 3f 6e [2] 71 62 [2] 7d 68 [2] 6a 63 [2] 71 2d [2] 4c }

  condition:
    any of them
}