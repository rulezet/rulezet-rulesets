rule TTP_XOR_MULT_DOSStub_724c {
  strings:
    $key_724c = { 26 24 [2] 52 3c [2] 15 3e [2] 52 2f [2] 1c 23 [2] 10 29 [2] 07 22 [2] 1c 6c [2] 21 }

  condition:
    any of them
}