rule TTP_XOR_MULT_DOSStub_94fc {
  strings:
    $key_94fc = { c0 94 [2] b4 8c [2] f3 8e [2] b4 9f [2] fa 93 [2] f6 99 [2] e1 92 [2] fa dc [2] c7 }

  condition:
    any of them
}