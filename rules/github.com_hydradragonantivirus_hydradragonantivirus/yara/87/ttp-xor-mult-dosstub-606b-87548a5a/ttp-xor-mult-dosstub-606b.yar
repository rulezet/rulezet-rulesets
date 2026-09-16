rule TTP_XOR_MULT_DOSStub_606b {
  strings:
    $key_606b = { 34 03 [2] 40 1b [2] 07 19 [2] 40 08 [2] 0e 04 [2] 02 0e [2] 15 05 [2] 0e 4b [2] 33 }

  condition:
    any of them
}