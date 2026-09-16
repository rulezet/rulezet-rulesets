rule TTP_XOR_MULT_DOSStub_361d {
  strings:
    $key_361d = { 62 75 [2] 16 6d [2] 51 6f [2] 16 7e [2] 58 72 [2] 54 78 [2] 43 73 [2] 58 3d [2] 65 }

  condition:
    any of them
}