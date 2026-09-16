rule TTP_XOR_MULT_DOSStub_856b {
  strings:
    $key_856b = { d1 03 [2] a5 1b [2] e2 19 [2] a5 08 [2] eb 04 [2] e7 0e [2] f0 05 [2] eb 4b [2] d6 }

  condition:
    any of them
}