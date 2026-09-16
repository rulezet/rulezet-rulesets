rule TTP_XOR_MULT_DOSStub_c34d {
  strings:
    $key_c34d = { 97 25 [2] e3 3d [2] a4 3f [2] e3 2e [2] ad 22 [2] a1 28 [2] b6 23 [2] ad 6d [2] 90 }

  condition:
    any of them
}