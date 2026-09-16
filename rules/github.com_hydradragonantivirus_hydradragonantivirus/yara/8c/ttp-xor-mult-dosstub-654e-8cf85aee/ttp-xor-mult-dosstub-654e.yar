rule TTP_XOR_MULT_DOSStub_654e {
  strings:
    $key_654e = { 31 26 [2] 45 3e [2] 02 3c [2] 45 2d [2] 0b 21 [2] 07 2b [2] 10 20 [2] 0b 6e [2] 36 }

  condition:
    any of them
}