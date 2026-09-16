rule TTP_XOR_MULT_DOSStub_653d {
  strings:
    $key_653d = { 31 55 [2] 45 4d [2] 02 4f [2] 45 5e [2] 0b 52 [2] 07 58 [2] 10 53 [2] 0b 1d [2] 36 }

  condition:
    any of them
}