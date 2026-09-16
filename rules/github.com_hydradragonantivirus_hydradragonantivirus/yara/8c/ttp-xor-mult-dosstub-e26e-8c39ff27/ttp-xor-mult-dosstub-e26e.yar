rule TTP_XOR_MULT_DOSStub_e26e {
  strings:
    $key_e26e = { b6 06 [2] c2 1e [2] 85 1c [2] c2 0d [2] 8c 01 [2] 80 0b [2] 97 00 [2] 8c 4e [2] b1 }

  condition:
    any of them
}