rule TTP_XOR_MULT_DOSStub_e50c {
  strings:
    $key_e50c = { b1 64 [2] c5 7c [2] 82 7e [2] c5 6f [2] 8b 63 [2] 87 69 [2] 90 62 [2] 8b 2c [2] b6 }

  condition:
    any of them
}