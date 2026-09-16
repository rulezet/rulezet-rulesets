rule TTP_XOR_MULT_DOSStub_946c {
  strings:
    $key_946c = { c0 04 [2] b4 1c [2] f3 1e [2] b4 0f [2] fa 03 [2] f6 09 [2] e1 02 [2] fa 4c [2] c7 }

  condition:
    any of them
}