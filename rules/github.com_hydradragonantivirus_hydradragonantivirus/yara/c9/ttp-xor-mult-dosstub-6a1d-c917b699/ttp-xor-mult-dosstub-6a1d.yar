rule TTP_XOR_MULT_DOSStub_6a1d {
  strings:
    $key_6a1d = { 3e 75 [2] 4a 6d [2] 0d 6f [2] 4a 7e [2] 04 72 [2] 08 78 [2] 1f 73 [2] 04 3d [2] 39 }

  condition:
    any of them
}