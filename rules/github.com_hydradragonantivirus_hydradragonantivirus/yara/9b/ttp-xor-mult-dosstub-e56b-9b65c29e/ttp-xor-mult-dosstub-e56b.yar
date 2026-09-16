rule TTP_XOR_MULT_DOSStub_e56b {
  strings:
    $key_e56b = { b1 03 [2] c5 1b [2] 82 19 [2] c5 08 [2] 8b 04 [2] 87 0e [2] 90 05 [2] 8b 4b [2] b6 }

  condition:
    any of them
}