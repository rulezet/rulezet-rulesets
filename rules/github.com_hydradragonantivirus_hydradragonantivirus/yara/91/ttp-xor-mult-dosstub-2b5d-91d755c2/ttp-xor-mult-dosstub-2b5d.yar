rule TTP_XOR_MULT_DOSStub_2b5d {
  strings:
    $key_2b5d = { 7f 35 [2] 0b 2d [2] 4c 2f [2] 0b 3e [2] 45 32 [2] 49 38 [2] 5e 33 [2] 45 7d [2] 78 }

  condition:
    any of them
}