rule TTP_XOR_MULT_DOSStub_e86b {
  strings:
    $key_e86b = { bc 03 [2] c8 1b [2] 8f 19 [2] c8 08 [2] 86 04 [2] 8a 0e [2] 9d 05 [2] 86 4b [2] bb }

  condition:
    any of them
}