rule TTP_XOR_MULT_DOSStub_2b3d {
  strings:
    $key_2b3d = { 7f 55 [2] 0b 4d [2] 4c 4f [2] 0b 5e [2] 45 52 [2] 49 58 [2] 5e 53 [2] 45 1d [2] 78 }

  condition:
    any of them
}