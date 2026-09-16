rule TTP_XOR_MULT_DOSStub_240d {
  strings:
    $key_240d = { 70 65 [2] 04 7d [2] 43 7f [2] 04 6e [2] 4a 62 [2] 46 68 [2] 51 63 [2] 4a 2d [2] 77 }

  condition:
    any of them
}