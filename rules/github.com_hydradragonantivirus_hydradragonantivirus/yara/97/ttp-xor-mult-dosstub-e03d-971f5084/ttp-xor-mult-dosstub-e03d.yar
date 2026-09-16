rule TTP_XOR_MULT_DOSStub_e03d {
  strings:
    $key_e03d = { b4 55 [2] c0 4d [2] 87 4f [2] c0 5e [2] 8e 52 [2] 82 58 [2] 95 53 [2] 8e 1d [2] b3 }

  condition:
    any of them
}