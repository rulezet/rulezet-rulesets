rule TTP_XOR_MULT_DOSStub_3b0d {
  strings:
    $key_3b0d = { 6f 65 [2] 1b 7d [2] 5c 7f [2] 1b 6e [2] 55 62 [2] 59 68 [2] 4e 63 [2] 55 2d [2] 68 }

  condition:
    any of them
}