rule TTP_XOR_MULT_DOSStub_052d {
  strings:
    $key_052d = { 51 45 [2] 25 5d [2] 62 5f [2] 25 4e [2] 6b 42 [2] 67 48 [2] 70 43 [2] 6b 0d [2] 56 }

  condition:
    any of them
}