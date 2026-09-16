rule TTP_XOR_MULT_DOSStub_976b {
  strings:
    $key_976b = { c3 03 [2] b7 1b [2] f0 19 [2] b7 08 [2] f9 04 [2] f5 0e [2] e2 05 [2] f9 4b [2] c4 }

  condition:
    any of them
}