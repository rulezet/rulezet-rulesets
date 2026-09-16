rule TTP_XOR_MULT_DOSStub_876b {
  strings:
    $key_876b = { d3 03 [2] a7 1b [2] e0 19 [2] a7 08 [2] e9 04 [2] e5 0e [2] f2 05 [2] e9 4b [2] d4 }

  condition:
    any of them
}