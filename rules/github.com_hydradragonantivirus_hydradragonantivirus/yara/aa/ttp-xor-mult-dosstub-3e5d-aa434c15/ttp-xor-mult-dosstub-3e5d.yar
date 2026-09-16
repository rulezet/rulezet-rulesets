rule TTP_XOR_MULT_DOSStub_3e5d {
  strings:
    $key_3e5d = { 6a 35 [2] 1e 2d [2] 59 2f [2] 1e 3e [2] 50 32 [2] 5c 38 [2] 4b 33 [2] 50 7d [2] 6d }

  condition:
    any of them
}