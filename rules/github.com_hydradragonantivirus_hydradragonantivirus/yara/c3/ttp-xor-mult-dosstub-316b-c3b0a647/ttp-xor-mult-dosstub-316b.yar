rule TTP_XOR_MULT_DOSStub_316b {
  strings:
    $key_316b = { 65 03 [2] 11 1b [2] 56 19 [2] 11 08 [2] 5f 04 [2] 53 0e [2] 44 05 [2] 5f 4b [2] 62 }

  condition:
    any of them
}