rule TTP_XOR_MULT_DOSStub_e031 {
  strings:
    $key_e031 = { b4 59 [2] c0 41 [2] 87 43 [2] c0 52 [2] 8e 5e [2] 82 54 [2] 95 5f [2] 8e 11 [2] b3 }

  condition:
    any of them
}