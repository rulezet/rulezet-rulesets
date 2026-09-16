rule TTP_XOR_MULT_DOSStub_2b7d {
  strings:
    $key_2b7d = { 7f 15 [2] 0b 0d [2] 4c 0f [2] 0b 1e [2] 45 12 [2] 49 18 [2] 5e 13 [2] 45 5d [2] 78 }

  condition:
    any of them
}