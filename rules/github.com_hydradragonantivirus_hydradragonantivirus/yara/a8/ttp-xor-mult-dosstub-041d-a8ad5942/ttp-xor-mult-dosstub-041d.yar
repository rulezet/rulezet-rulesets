rule TTP_XOR_MULT_DOSStub_041d {
  strings:
    $key_041d = { 50 75 [2] 24 6d [2] 63 6f [2] 24 7e [2] 6a 72 [2] 66 78 [2] 71 73 [2] 6a 3d [2] 57 }

  condition:
    any of them
}