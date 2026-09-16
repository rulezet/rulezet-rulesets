rule TTP_XOR_MULT_DOSStub_116b {
  strings:
    $key_116b = { 45 03 [2] 31 1b [2] 76 19 [2] 31 08 [2] 7f 04 [2] 73 0e [2] 64 05 [2] 7f 4b [2] 42 }

  condition:
    any of them
}