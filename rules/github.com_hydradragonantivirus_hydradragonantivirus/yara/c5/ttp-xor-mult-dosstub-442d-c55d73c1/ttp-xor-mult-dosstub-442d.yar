rule TTP_XOR_MULT_DOSStub_442d {
  strings:
    $key_442d = { 10 45 [2] 64 5d [2] 23 5f [2] 64 4e [2] 2a 42 [2] 26 48 [2] 31 43 [2] 2a 0d [2] 17 }

  condition:
    any of them
}