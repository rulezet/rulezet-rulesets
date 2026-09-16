rule TTP_XOR_MULT_DOSStub_571d {
  strings:
    $key_571d = { 03 75 [2] 77 6d [2] 30 6f [2] 77 7e [2] 39 72 [2] 35 78 [2] 22 73 [2] 39 3d [2] 04 }

  condition:
    any of them
}