rule TTP_XOR_MULT_DOSStub_966c {
  strings:
    $key_966c = { c2 04 [2] b6 1c [2] f1 1e [2] b6 0f [2] f8 03 [2] f4 09 [2] e3 02 [2] f8 4c [2] c5 }

  condition:
    any of them
}