rule TTP_XOR_MULT_DOSStub_0b3d {
  strings:
    $key_0b3d = { 5f 55 [2] 2b 4d [2] 6c 4f [2] 2b 5e [2] 65 52 [2] 69 58 [2] 7e 53 [2] 65 1d [2] 58 }

  condition:
    any of them
}