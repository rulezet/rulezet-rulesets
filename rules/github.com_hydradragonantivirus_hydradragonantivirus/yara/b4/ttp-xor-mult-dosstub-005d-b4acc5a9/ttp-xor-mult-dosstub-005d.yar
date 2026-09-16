rule TTP_XOR_MULT_DOSStub_005d {
  strings:
    $key_005d = { 54 35 [2] 20 2d [2] 67 2f [2] 20 3e [2] 6e 32 [2] 62 38 [2] 75 33 [2] 6e 7d [2] 53 }

  condition:
    any of them
}