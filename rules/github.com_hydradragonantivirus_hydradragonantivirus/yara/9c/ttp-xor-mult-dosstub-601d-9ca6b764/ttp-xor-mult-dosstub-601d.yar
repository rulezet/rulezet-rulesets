rule TTP_XOR_MULT_DOSStub_601d {
  strings:
    $key_601d = { 34 75 [2] 40 6d [2] 07 6f [2] 40 7e [2] 0e 72 [2] 02 78 [2] 15 73 [2] 0e 3d [2] 33 }

  condition:
    any of them
}