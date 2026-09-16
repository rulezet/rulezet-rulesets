rule TTP_XOR_MULT_DOSStub_946b {
  strings:
    $key_946b = { c0 03 [2] b4 1b [2] f3 19 [2] b4 08 [2] fa 04 [2] f6 0e [2] e1 05 [2] fa 4b [2] c7 }

  condition:
    any of them
}