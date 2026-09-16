rule TTP_XOR_MULT_DOSStub_1e3d {
  strings:
    $key_1e3d = { 4a 55 [2] 3e 4d [2] 79 4f [2] 3e 5e [2] 70 52 [2] 7c 58 [2] 6b 53 [2] 70 1d [2] 4d }

  condition:
    any of them
}