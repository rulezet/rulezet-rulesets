rule TTP_XOR_MULT_DOSStub_c76c {
  strings:
    $key_c76c = { 93 04 [2] e7 1c [2] a0 1e [2] e7 0f [2] a9 03 [2] a5 09 [2] b2 02 [2] a9 4c [2] 94 }

  condition:
    any of them
}