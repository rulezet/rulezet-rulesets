rule TTP_XOR_MULT_DOSStub_c36d {
  strings:
    $key_c36d = { 97 05 [2] e3 1d [2] a4 1f [2] e3 0e [2] ad 02 [2] a1 08 [2] b6 03 [2] ad 4d [2] 90 }

  condition:
    any of them
}