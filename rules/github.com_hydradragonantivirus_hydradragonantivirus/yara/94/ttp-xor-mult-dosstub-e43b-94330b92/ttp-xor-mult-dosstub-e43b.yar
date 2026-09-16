rule TTP_XOR_MULT_DOSStub_e43b {
  strings:
    $key_e43b = { b0 53 [2] c4 4b [2] 83 49 [2] c4 58 [2] 8a 54 [2] 86 5e [2] 91 55 [2] 8a 1b [2] b7 }

  condition:
    any of them
}