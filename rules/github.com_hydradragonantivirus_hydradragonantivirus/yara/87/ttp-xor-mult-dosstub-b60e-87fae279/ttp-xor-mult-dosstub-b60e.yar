rule TTP_XOR_MULT_DOSStub_b60e {
  strings:
    $key_b60e = { e2 66 [2] 96 7e [2] d1 7c [2] 96 6d [2] d8 61 [2] d4 6b [2] c3 60 [2] d8 2e [2] e5 }

  condition:
    any of them
}