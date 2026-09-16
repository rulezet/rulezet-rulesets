rule TTP_XOR_MULT_DOSStub_84eb {
  strings:
    $key_84eb = { d0 83 [2] a4 9b [2] e3 99 [2] a4 88 [2] ea 84 [2] e6 8e [2] f1 85 [2] ea cb [2] d7 }

  condition:
    any of them
}