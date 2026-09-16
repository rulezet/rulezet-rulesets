rule TTP_XOR_MULT_DOSStub_3f0d {
  strings:
    $key_3f0d = { 6b 65 [2] 1f 7d [2] 58 7f [2] 1f 6e [2] 51 62 [2] 5d 68 [2] 4a 63 [2] 51 2d [2] 6c }

  condition:
    any of them
}