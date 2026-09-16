rule TTP_XOR_MULT_DOSStub_3b1d {
  strings:
    $key_3b1d = { 6f 75 [2] 1b 6d [2] 5c 6f [2] 1b 7e [2] 55 72 [2] 59 78 [2] 4e 73 [2] 55 3d [2] 68 }

  condition:
    any of them
}