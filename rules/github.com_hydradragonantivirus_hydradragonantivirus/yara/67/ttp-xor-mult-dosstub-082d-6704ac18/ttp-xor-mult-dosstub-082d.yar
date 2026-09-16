rule TTP_XOR_MULT_DOSStub_082d {
  strings:
    $key_082d = { 5c 45 [2] 28 5d [2] 6f 5f [2] 28 4e [2] 66 42 [2] 6a 48 [2] 7d 43 [2] 66 0d [2] 5b }

  condition:
    any of them
}