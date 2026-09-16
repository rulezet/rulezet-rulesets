rule TTP_XOR_MULT_DOSStub_843c {
  strings:
    $key_843c = { d0 54 [2] a4 4c [2] e3 4e [2] a4 5f [2] ea 53 [2] e6 59 [2] f1 52 [2] ea 1c [2] d7 }

  condition:
    any of them
}