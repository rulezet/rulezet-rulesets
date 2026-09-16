rule TTP_XOR_MULT_DOSStub_833d {
  strings:
    $key_833d = { d7 55 [2] a3 4d [2] e4 4f [2] a3 5e [2] ed 52 [2] e1 58 [2] f6 53 [2] ed 1d [2] d0 }

  condition:
    any of them
}