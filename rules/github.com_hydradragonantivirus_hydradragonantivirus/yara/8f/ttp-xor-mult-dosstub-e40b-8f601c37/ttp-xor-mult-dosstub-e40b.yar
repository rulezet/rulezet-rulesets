rule TTP_XOR_MULT_DOSStub_e40b {
  strings:
    $key_e40b = { b0 63 [2] c4 7b [2] 83 79 [2] c4 68 [2] 8a 64 [2] 86 6e [2] 91 65 [2] 8a 2b [2] b7 }

  condition:
    any of them
}