rule TTP_XOR_MULT_DOSStub_d06b {
  strings:
    $key_d06b = { 84 03 [2] f0 1b [2] b7 19 [2] f0 08 [2] be 04 [2] b2 0e [2] a5 05 [2] be 4b [2] 83 }

  condition:
    any of them
}