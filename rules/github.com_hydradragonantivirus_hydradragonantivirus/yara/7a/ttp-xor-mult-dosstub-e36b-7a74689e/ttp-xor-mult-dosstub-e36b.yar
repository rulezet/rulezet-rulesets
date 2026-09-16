rule TTP_XOR_MULT_DOSStub_e36b {
  strings:
    $key_e36b = { b7 03 [2] c3 1b [2] 84 19 [2] c3 08 [2] 8d 04 [2] 81 0e [2] 96 05 [2] 8d 4b [2] b0 }

  condition:
    any of them
}