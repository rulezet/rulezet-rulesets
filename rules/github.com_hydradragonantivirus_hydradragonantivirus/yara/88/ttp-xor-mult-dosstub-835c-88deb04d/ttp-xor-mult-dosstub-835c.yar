rule TTP_XOR_MULT_DOSStub_835c {
  strings:
    $key_835c = { d7 34 [2] a3 2c [2] e4 2e [2] a3 3f [2] ed 33 [2] e1 39 [2] f6 32 [2] ed 7c [2] d0 }

  condition:
    any of them
}