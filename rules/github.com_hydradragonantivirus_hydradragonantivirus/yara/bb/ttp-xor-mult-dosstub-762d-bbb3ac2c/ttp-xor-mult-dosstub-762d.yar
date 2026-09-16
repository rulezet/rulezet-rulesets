rule TTP_XOR_MULT_DOSStub_762d {
  strings:
    $key_762d = { 22 45 [2] 56 5d [2] 11 5f [2] 56 4e [2] 18 42 [2] 14 48 [2] 03 43 [2] 18 0d [2] 25 }

  condition:
    any of them
}