rule TTP_XOR_MULT_DOSStub_c70c {
  strings:
    $key_c70c = { 93 64 [2] e7 7c [2] a0 7e [2] e7 6f [2] a9 63 [2] a5 69 [2] b2 62 [2] a9 2c [2] 94 }

  condition:
    any of them
}