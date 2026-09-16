rule TTP_XOR_MULT_DOSStub_e56d {
  strings:
    $key_e56d = { b1 05 [2] c5 1d [2] 82 1f [2] c5 0e [2] 8b 02 [2] 87 08 [2] 90 03 [2] 8b 4d [2] b6 }

  condition:
    any of them
}