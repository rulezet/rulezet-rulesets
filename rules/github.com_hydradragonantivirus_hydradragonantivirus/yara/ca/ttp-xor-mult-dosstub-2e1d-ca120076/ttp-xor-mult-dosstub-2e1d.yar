rule TTP_XOR_MULT_DOSStub_2e1d {
  strings:
    $key_2e1d = { 7a 75 [2] 0e 6d [2] 49 6f [2] 0e 7e [2] 40 72 [2] 4c 78 [2] 5b 73 [2] 40 3d [2] 7d }

  condition:
    any of them
}