rule TTP_XOR_MULT_DOSStub_0e3d {
  strings:
    $key_0e3d = { 5a 55 [2] 2e 4d [2] 69 4f [2] 2e 5e [2] 60 52 [2] 6c 58 [2] 7b 53 [2] 60 1d [2] 5d }

  condition:
    any of them
}