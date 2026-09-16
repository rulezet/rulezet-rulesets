rule TTP_XOR_MULT_DOSStub_e06d {
  strings:
    $key_e06d = { b4 05 [2] c0 1d [2] 87 1f [2] c0 0e [2] 8e 02 [2] 82 08 [2] 95 03 [2] 8e 4d [2] b3 }

  condition:
    any of them
}