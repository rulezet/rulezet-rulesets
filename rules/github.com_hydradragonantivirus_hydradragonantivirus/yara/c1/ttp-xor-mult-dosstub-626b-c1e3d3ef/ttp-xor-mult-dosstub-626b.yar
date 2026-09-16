rule TTP_XOR_MULT_DOSStub_626b {
  strings:
    $key_626b = { 36 03 [2] 42 1b [2] 05 19 [2] 42 08 [2] 0c 04 [2] 00 0e [2] 17 05 [2] 0c 4b [2] 31 }

  condition:
    any of them
}