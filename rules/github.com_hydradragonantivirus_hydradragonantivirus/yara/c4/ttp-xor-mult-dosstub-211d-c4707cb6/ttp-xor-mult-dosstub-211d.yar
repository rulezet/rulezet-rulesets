rule TTP_XOR_MULT_DOSStub_211d {
  strings:
    $key_211d = { 75 75 [2] 01 6d [2] 46 6f [2] 01 7e [2] 4f 72 [2] 43 78 [2] 54 73 [2] 4f 3d [2] 72 }

  condition:
    any of them
}