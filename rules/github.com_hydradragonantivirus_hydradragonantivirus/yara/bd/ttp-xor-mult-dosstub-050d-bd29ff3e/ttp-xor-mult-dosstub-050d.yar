rule TTP_XOR_MULT_DOSStub_050d {
  strings:
    $key_050d = { 51 65 [2] 25 7d [2] 62 7f [2] 25 6e [2] 6b 62 [2] 67 68 [2] 70 63 [2] 6b 2d [2] 56 }

  condition:
    any of them
}