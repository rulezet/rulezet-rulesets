rule TTP_XOR_MULT_DOSStub_2e3d {
  strings:
    $key_2e3d = { 7a 55 [2] 0e 4d [2] 49 4f [2] 0e 5e [2] 40 52 [2] 4c 58 [2] 5b 53 [2] 40 1d [2] 7d }

  condition:
    any of them
}