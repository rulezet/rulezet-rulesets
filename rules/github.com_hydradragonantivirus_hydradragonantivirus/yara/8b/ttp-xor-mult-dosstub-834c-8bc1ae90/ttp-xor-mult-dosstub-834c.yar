rule TTP_XOR_MULT_DOSStub_834c {
  strings:
    $key_834c = { d7 24 [2] a3 3c [2] e4 3e [2] a3 2f [2] ed 23 [2] e1 29 [2] f6 22 [2] ed 6c [2] d0 }

  condition:
    any of them
}