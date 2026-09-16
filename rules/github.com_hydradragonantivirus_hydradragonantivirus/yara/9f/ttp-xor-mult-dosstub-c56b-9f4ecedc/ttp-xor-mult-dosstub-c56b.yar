rule TTP_XOR_MULT_DOSStub_c56b {
  strings:
    $key_c56b = { 91 03 [2] e5 1b [2] a2 19 [2] e5 08 [2] ab 04 [2] a7 0e [2] b0 05 [2] ab 4b [2] 96 }

  condition:
    any of them
}