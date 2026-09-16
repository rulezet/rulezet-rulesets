rule TTP_XOR_MULT_DOSStub_942c {
  strings:
    $key_942c = { c0 44 [2] b4 5c [2] f3 5e [2] b4 4f [2] fa 43 [2] f6 49 [2] e1 42 [2] fa 0c [2] c7 }

  condition:
    any of them
}