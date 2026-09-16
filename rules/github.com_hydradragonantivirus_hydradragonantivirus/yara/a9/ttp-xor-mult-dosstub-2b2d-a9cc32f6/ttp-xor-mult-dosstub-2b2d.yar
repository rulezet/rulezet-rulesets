rule TTP_XOR_MULT_DOSStub_2b2d {
  strings:
    $key_2b2d = { 7f 45 [2] 0b 5d [2] 4c 5f [2] 0b 4e [2] 45 42 [2] 49 48 [2] 5e 43 [2] 45 0d [2] 78 }

  condition:
    any of them
}