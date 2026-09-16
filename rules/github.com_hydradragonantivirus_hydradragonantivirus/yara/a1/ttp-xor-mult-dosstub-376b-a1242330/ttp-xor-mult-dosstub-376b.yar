rule TTP_XOR_MULT_DOSStub_376b {
  strings:
    $key_376b = { 63 03 [2] 17 1b [2] 50 19 [2] 17 08 [2] 59 04 [2] 55 0e [2] 42 05 [2] 59 4b [2] 64 }

  condition:
    any of them
}