rule TTP_XOR_MULT_DOSStub_032d {
  strings:
    $key_032d = { 57 45 [2] 23 5d [2] 64 5f [2] 23 4e [2] 6d 42 [2] 61 48 [2] 76 43 [2] 6d 0d [2] 50 }

  condition:
    any of them
}