rule TTP_XOR_MULT_DOSStub_2f0d {
  strings:
    $key_2f0d = { 7b 65 [2] 0f 7d [2] 48 7f [2] 0f 6e [2] 41 62 [2] 4d 68 [2] 5a 63 [2] 41 2d [2] 7c }

  condition:
    any of them
}