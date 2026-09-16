rule TTP_XOR_MULT_DOSStub_852c {
  strings:
    $key_852c = { d1 44 [2] a5 5c [2] e2 5e [2] a5 4f [2] eb 43 [2] e7 49 [2] f0 42 [2] eb 0c [2] d6 }

  condition:
    any of them
}