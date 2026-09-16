rule TTP_XOR_MULT_DOSStub_e46b {
  strings:
    $key_e46b = { b0 03 [2] c4 1b [2] 83 19 [2] c4 08 [2] 8a 04 [2] 86 0e [2] 91 05 [2] 8a 4b [2] b7 }

  condition:
    any of them
}