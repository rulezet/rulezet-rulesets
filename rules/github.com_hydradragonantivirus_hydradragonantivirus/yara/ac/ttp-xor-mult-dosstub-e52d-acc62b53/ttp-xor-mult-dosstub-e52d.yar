rule TTP_XOR_MULT_DOSStub_e52d {
  strings:
    $key_e52d = { b1 45 [2] c5 5d [2] 82 5f [2] c5 4e [2] 8b 42 [2] 87 48 [2] 90 43 [2] 8b 0d [2] b6 }

  condition:
    any of them
}