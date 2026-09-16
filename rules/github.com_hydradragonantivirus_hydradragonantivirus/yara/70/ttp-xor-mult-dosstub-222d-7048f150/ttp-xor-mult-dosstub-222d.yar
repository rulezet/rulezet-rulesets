rule TTP_XOR_MULT_DOSStub_222d {
  strings:
    $key_222d = { 76 45 [2] 02 5d [2] 45 5f [2] 02 4e [2] 4c 42 [2] 40 48 [2] 57 43 [2] 4c 0d [2] 71 }

  condition:
    any of them
}