rule TTP_XOR_MULT_DOSStub_721d {
  strings:
    $key_721d = { 26 75 [2] 52 6d [2] 15 6f [2] 52 7e [2] 1c 72 [2] 10 78 [2] 07 73 [2] 1c 3d [2] 21 }

  condition:
    any of them
}