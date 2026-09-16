rule TTP_XOR_MULT_DOSStub_0e5d {
  strings:
    $key_0e5d = { 5a 35 [2] 2e 2d [2] 69 2f [2] 2e 3e [2] 60 32 [2] 6c 38 [2] 7b 33 [2] 60 7d [2] 5d }

  condition:
    any of them
}