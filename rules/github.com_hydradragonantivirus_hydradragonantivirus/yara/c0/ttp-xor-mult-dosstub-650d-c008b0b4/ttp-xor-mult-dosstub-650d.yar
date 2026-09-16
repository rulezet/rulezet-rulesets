rule TTP_XOR_MULT_DOSStub_650d {
  strings:
    $key_650d = { 31 65 [2] 45 7d [2] 02 7f [2] 45 6e [2] 0b 62 [2] 07 68 [2] 10 63 [2] 0b 2d [2] 36 }

  condition:
    any of them
}