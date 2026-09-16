rule TTP_XOR_MULT_DOSStub_722c {
  strings:
    $key_722c = { 26 44 [2] 52 5c [2] 15 5e [2] 52 4f [2] 1c 43 [2] 10 49 [2] 07 42 [2] 1c 0c [2] 21 }

  condition:
    any of them
}