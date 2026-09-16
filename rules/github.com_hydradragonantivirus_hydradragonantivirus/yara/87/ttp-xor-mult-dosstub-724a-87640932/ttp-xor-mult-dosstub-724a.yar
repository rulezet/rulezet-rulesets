rule TTP_XOR_MULT_DOSStub_724a {
  strings:
    $key_724a = { 26 22 [2] 52 3a [2] 15 38 [2] 52 29 [2] 1c 25 [2] 10 2f [2] 07 24 [2] 1c 6a [2] 21 }

  condition:
    any of them
}