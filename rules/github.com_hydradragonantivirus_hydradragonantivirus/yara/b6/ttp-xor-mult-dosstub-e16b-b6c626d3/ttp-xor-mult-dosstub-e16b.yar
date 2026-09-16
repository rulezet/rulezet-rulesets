rule TTP_XOR_MULT_DOSStub_e16b {
  strings:
    $key_e16b = { b5 03 [2] c1 1b [2] 86 19 [2] c1 08 [2] 8f 04 [2] 83 0e [2] 94 05 [2] 8f 4b [2] b2 }

  condition:
    any of them
}