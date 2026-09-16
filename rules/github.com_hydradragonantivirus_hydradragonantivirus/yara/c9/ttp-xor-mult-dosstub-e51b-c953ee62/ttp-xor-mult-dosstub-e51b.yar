rule TTP_XOR_MULT_DOSStub_e51b {
  strings:
    $key_e51b = { b1 73 [2] c5 6b [2] 82 69 [2] c5 78 [2] 8b 74 [2] 87 7e [2] 90 75 [2] 8b 3b [2] b6 }

  condition:
    any of them
}