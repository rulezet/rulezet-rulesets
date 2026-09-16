rule TTP_XOR_MULT_DOSStub_936b {
  strings:
    $key_936b = { c7 03 [2] b3 1b [2] f4 19 [2] b3 08 [2] fd 04 [2] f1 0e [2] e6 05 [2] fd 4b [2] c0 }

  condition:
    any of them
}