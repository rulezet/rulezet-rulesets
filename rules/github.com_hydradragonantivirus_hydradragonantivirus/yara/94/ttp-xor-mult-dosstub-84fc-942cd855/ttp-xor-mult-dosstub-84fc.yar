rule TTP_XOR_MULT_DOSStub_84fc {
  strings:
    $key_84fc = { d0 94 [2] a4 8c [2] e3 8e [2] a4 9f [2] ea 93 [2] e6 99 [2] f1 92 [2] ea dc [2] d7 }

  condition:
    any of them
}