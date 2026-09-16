rule TTP_XOR_MULT_DOSStub_284e {
  strings:
    $key_284e = { 7c 26 [2] 08 3e [2] 4f 3c [2] 08 2d [2] 46 21 [2] 4a 2b [2] 5d 20 [2] 46 6e [2] 7b }

  condition:
    any of them
}