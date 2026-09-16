rule TTP_XOR_MULT_DOSStub_c56d {
  strings:
    $key_c56d = { 91 05 [2] e5 1d [2] a2 1f [2] e5 0e [2] ab 02 [2] a7 08 [2] b0 03 [2] ab 4d [2] 96 }

  condition:
    any of them
}