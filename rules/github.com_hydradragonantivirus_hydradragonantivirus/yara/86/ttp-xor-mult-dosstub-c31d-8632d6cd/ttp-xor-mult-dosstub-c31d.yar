rule TTP_XOR_MULT_DOSStub_c31d {
  strings:
    $key_c31d = { 97 75 [2] e3 6d [2] a4 6f [2] e3 7e [2] ad 72 [2] a1 78 [2] b6 73 [2] ad 3d [2] 90 }

  condition:
    any of them
}