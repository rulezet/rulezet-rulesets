rule TTP_XOR_MULT_DOSStub_231d {
  strings:
    $key_231d = { 77 75 [2] 03 6d [2] 44 6f [2] 03 7e [2] 4d 72 [2] 41 78 [2] 56 73 [2] 4d 3d [2] 70 }

  condition:
    any of them
}