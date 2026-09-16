rule TTP_XOR_MULT_DOSStub_0b5d {
  strings:
    $key_0b5d = { 5f 35 [2] 2b 2d [2] 6c 2f [2] 2b 3e [2] 65 32 [2] 69 38 [2] 7e 33 [2] 65 7d [2] 58 }

  condition:
    any of them
}