rule TTP_XOR_MULT_DOSStub_c06b {
  strings:
    $key_c06b = { 94 03 [2] e0 1b [2] a7 19 [2] e0 08 [2] ae 04 [2] a2 0e [2] b5 05 [2] ae 4b [2] 93 }

  condition:
    any of them
}