rule TTP_XOR_MULT_DOSStub_c57d {
  strings:
    $key_c57d = { 91 15 [2] e5 0d [2] a2 0f [2] e5 1e [2] ab 12 [2] a7 18 [2] b0 13 [2] ab 5d [2] 96 }

  condition:
    any of them
}