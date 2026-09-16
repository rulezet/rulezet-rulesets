rule TTP_XOR_MULT_DOSStub_661d {
  strings:
    $key_661d = { 32 75 [2] 46 6d [2] 01 6f [2] 46 7e [2] 08 72 [2] 04 78 [2] 13 73 [2] 08 3d [2] 35 }

  condition:
    any of them
}