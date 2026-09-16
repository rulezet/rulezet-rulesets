rule TTP_XOR_MULT_DOSStub_062d {
  strings:
    $key_062d = { 52 45 [2] 26 5d [2] 61 5f [2] 26 4e [2] 68 42 [2] 64 48 [2] 73 43 [2] 68 0d [2] 55 }

  condition:
    any of them
}