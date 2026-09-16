rule TTP_XOR_MULT_DOSStub_076b {
  strings:
    $key_076b = { 53 03 [2] 27 1b [2] 60 19 [2] 27 08 [2] 69 04 [2] 65 0e [2] 72 05 [2] 69 4b [2] 54 }

  condition:
    any of them
}